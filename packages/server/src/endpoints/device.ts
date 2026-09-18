import { authenticateClient } from '../client-auth'
import type { ResolvedConfig } from '../config'
import { OAuthError } from '../errors'
import { token } from '../random'
import type { Artifact } from '../types'

/**
 * Base32 without the characters a person misreads aloud or in a bad font: no 0/O, 1/I/L, U (which
 * is heard as V). RFC 8628 §6.1 asks for a user code that is easy to transcribe, and this is the
 * part that decides whether the flow works on a television.
 */
const ALPHABET = 'BCDFGHJKMNPQRSTVWXYZ23456789'
const GROUPS = 2
const GROUP_SIZE = 4

export const userCode = () => {
  const bytes = new Uint8Array(GROUPS * GROUP_SIZE)
  crypto.getRandomValues(bytes)
  const characters = [...bytes].map(byte => ALPHABET[byte % ALPHABET.length] as string)
  return Array.from({ length: GROUPS }, (_, group) => characters.slice(group * GROUP_SIZE, (group + 1) * GROUP_SIZE).join('')).join('-')
}

export const normalizeUserCode = (input: string) => input.toUpperCase().replace(/[^A-Z0-9]/g, '')

const DEFAULT_INTERVAL = 5

export const deviceAuthorizationEndpoint = async (config: ResolvedConfig, request: Request) => {
  const form = new URLSearchParams(await request.text())
  const { client } = await authenticateClient(config, form, request.headers)

  const scopes = (form.get('scope') ?? 'openid').split(' ').filter(Boolean)
  const unallowed = scopes.filter(scope => !client.scopes.includes(scope))
  if (unallowed.length)
    throw new OAuthError('invalid_scope', { description: `client ${client.clientId} may not request: ${unallowed.join(', ')}` })

  const deviceCode = token()
  const code = userCode()
  const expiresIn = config.ttl.deviceCode
  const expiresAt = new Date(Date.now() + expiresIn * 1000)

  await config.adapter.artifacts.upsert({
    id: deviceCode,
    kind: 'device_code',
    clientId: client.clientId,
    // The user code is indexed by the adapter, because this is looked up by a person typing it.
    payload: { userCode: normalizeUserCode(code), scopes, status: 'pending', interval: DEFAULT_INTERVAL },
    expiresAt
  })

  const verificationUri = `${config.issuer}${config.routes.deviceVerification}`
  return Response.json(
    {
      device_code: deviceCode,
      user_code: code,
      verification_uri: verificationUri,
      verification_uri_complete: `${verificationUri}?user_code=${encodeURIComponent(code)}`,
      expires_in: expiresIn,
      interval: DEFAULT_INTERVAL
    },
    { status: 200, headers: { 'cache-control': 'no-store', pragma: 'no-cache' } }
  )
}

export type DevicePayload = {
  userCode: string
  scopes: string[]
  status: 'pending' | 'approved' | 'denied'
  interval: number
  accountId?: string
  sessionId?: string
  grantId?: string
  lastPolledAt?: number
}

const payloadOf = (artifact: Artifact) => artifact.payload as unknown as DevicePayload

/**
 * The device polls this; a person approves it elsewhere. Slow-down is enforced here rather than
 * trusted to the device, because a device that ignores `interval` is exactly the one to rate-limit
 * (RFC 8628 §3.5).
 */
export const consumeDeviceCode = async (config: ResolvedConfig, deviceCode: string, clientId: string) => {
  const artifact = await config.adapter.artifacts.find('device_code', deviceCode)
  if (!artifact) throw new OAuthError('expired_token', { description: 'the device code is unknown or expired', spec: 'RFC 8628 §3.5' })
  if (artifact.clientId !== clientId) throw new OAuthError('invalid_grant', { description: 'this device code belongs to another client' })

  const payload = payloadOf(artifact)
  const now = Date.now()
  const since = payload.lastPolledAt ? (now - payload.lastPolledAt) / 1000 : Number.POSITIVE_INFINITY

  if (since < payload.interval) {
    payload.interval += DEFAULT_INTERVAL
    payload.lastPolledAt = now
    await config.adapter.artifacts.upsert({ ...artifact, payload: payload as unknown as Record<string, unknown> })
    throw new OAuthError('slow_down', { description: `poll no more often than every ${payload.interval} seconds`, spec: 'RFC 8628 §3.5' })
  }

  payload.lastPolledAt = now
  await config.adapter.artifacts.upsert({ ...artifact, payload: payload as unknown as Record<string, unknown> })

  if (payload.status === 'denied') throw new OAuthError('access_denied', { description: 'the request was denied', spec: 'RFC 8628 §3.5' })
  if (payload.status === 'pending')
    throw new OAuthError('authorization_pending', { description: 'the user has not finished yet', spec: 'RFC 8628 §3.5' })

  // Single-use: approval redeems once, however many times the device polls.
  await config.adapter.artifacts.destroy('device_code', deviceCode)
  return { artifact, payload }
}

export type DeviceApproval = {
  accountId: string
  sessionId: string
  scopes: string[]
}

/** Looks up what a person typed, so a screen can show them what they are approving (FR-C7). */
export const findByUserCode = async (config: ResolvedConfig, typed: string) => {
  const artifact = await config.adapter.artifacts.findByUserCode?.(normalizeUserCode(typed))
  if (!artifact) return undefined
  const payload = payloadOf(artifact)
  const client = await config.adapter.clients.find(artifact.clientId)
  return client ? { artifact, payload, client } : undefined
}

export const resolveDeviceCode = async (config: ResolvedConfig, typed: string, outcome: DeviceApproval | { denied: true }) => {
  const found = await findByUserCode(config, typed)
  if (!found) throw new OAuthError('invalid_request', { description: 'that code is not one we are waiting for', status: 404 })
  if (found.payload.status !== 'pending') {
    throw new OAuthError('invalid_request', { description: 'that code has already been answered', status: 409 })
  }

  if ('denied' in outcome) {
    const payload = { ...found.payload, status: 'denied' as const }
    await config.adapter.artifacts.upsert({ ...found.artifact, payload: payload as unknown as Record<string, unknown> })
    return { approved: false as const, client: found.client }
  }

  const previous = await config.adapter.grants.findByAccountAndClient(outcome.accountId, found.artifact.clientId)
  const grant = {
    id: previous?.id ?? token(),
    accountId: outcome.accountId,
    clientId: found.artifact.clientId,
    scopes: [...new Set([...(previous?.scopes ?? []), ...outcome.scopes])],
    claims: previous?.claims ?? [],
    resources: previous?.resources ?? {},
    createdAt: previous?.createdAt ?? new Date()
  }
  await config.adapter.grants.upsert(grant)

  const payload = {
    ...found.payload,
    status: 'approved' as const,
    accountId: outcome.accountId,
    sessionId: outcome.sessionId,
    grantId: grant.id
  }
  await config.adapter.artifacts.upsert({
    ...found.artifact,
    accountId: outcome.accountId,
    grantId: grant.id,
    payload: payload as unknown as Record<string, unknown>
  })
  return { approved: true as const, client: found.client }
}
