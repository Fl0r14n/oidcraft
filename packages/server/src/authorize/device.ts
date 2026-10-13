import { randomString } from '@oidcraft/core'
import { authenticateClient } from '../clients/authenticate'
import type { ResolvedConfig } from '../config'
import type { ClientCertificate } from '../context'
import { OAuthError } from '../errors'
import { type Binding, issueTokens } from '../token/issue'
import type { Artifact, Client } from '../types'
import { checkApproval } from './approval'

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

export const deviceAuthorizationEndpoint = async (
  config: ResolvedConfig,
  request: Request,
  certificate?: ClientCertificate | undefined
) => {
  const form = new URLSearchParams(await request.text())
  const { client } = await authenticateClient(config, form, request.headers, certificate)

  const scopes = (form.get('scope') ?? 'openid').split(' ').filter(Boolean)
  const unallowed = scopes.filter(scope => !client.scopes.includes(scope))
  if (unallowed.length)
    throw new OAuthError('invalid_scope', { description: `client ${client.clientId} may not request: ${unallowed.join(', ')}` })

  const deviceCode = randomString()
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
const consumeDeviceCode = async (config: ResolvedConfig, deviceCode: string, clientId: string) => {
  const artifact = await config.adapter.artifacts.find('device_code', deviceCode)
  if (!artifact) throw new OAuthError('expired_token', { description: 'the device code is unknown or expired', spec: 'RFC 8628 §3.5' })
  if (artifact.clientId !== clientId) throw new OAuthError('invalid_grant', { description: 'this device code belongs to another client' })
  if (artifact.consumedAt)
    throw new OAuthError('invalid_grant', { description: 'this device code was already redeemed', spec: 'RFC 8628 §3.5' })

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

  // Single-use: approval redeems once, however many times the device polls (NFR-S4).
  if (!(await config.adapter.artifacts.consume('device_code', deviceCode))) {
    throw new OAuthError('invalid_grant', { description: 'this device code was already redeemed', spec: 'RFC 8628 §3.5' })
  }
  await config.adapter.artifacts.destroy('device_code', deviceCode)
  return { artifact, payload }
}

export type DeviceApproval = {
  accountId: string
  sessionId: string
  scopes: string[]
}

const ATTEMPT_WINDOW_SECONDS = 600
const MAX_FAILURES = 5
// Without a peer address every guesser shares one bucket, so it is wider, or one person locks out all.
const MAX_ANONYMOUS_FAILURES = 50

/** Who is typing codes, as far as the host can tell. Only the peer address counts (FR-R4). */
export type UserCodeContext = { clientIp?: string | undefined }

/**
 * RFC 8628 §5.1: a user code is short enough to guess, so wrong guesses are limited per peer.
 * A read-then-write count can let a burst through a few over the limit; it bounds guessing, it is
 * not an exact quota.
 */
const attemptsFor = async (config: ResolvedConfig, context: UserCodeContext) => {
  const id = context.clientIp ? `ip:${context.clientIp}` : 'anonymous'
  const limit = context.clientIp ? MAX_FAILURES : MAX_ANONYMOUS_FAILURES
  const record = await config.adapter.artifacts.find('user_code_attempts', id)
  const failures = (record?.payload.failures as number | undefined) ?? 0
  if (failures >= limit) {
    throw new OAuthError('invalid_request', { description: 'too many wrong codes; try again later', spec: 'RFC 8628 §5.1', status: 429 })
  }
  return async () => {
    await config.adapter.artifacts.upsert({
      id,
      kind: 'user_code_attempts',
      clientId: '',
      payload: { failures: failures + 1 },
      expiresAt: record?.expiresAt ?? new Date(Date.now() + ATTEMPT_WINDOW_SECONDS * 1000)
    })
  }
}

/** Looks up what a person typed, so a screen can show them what they are approving (FR-C7). */
export const findByUserCode = async (config: ResolvedConfig, typed: string, context: UserCodeContext = {}) => {
  const recordFailure = await attemptsFor(config, context)
  const artifact = await config.adapter.artifacts.findByUserCode?.(normalizeUserCode(typed))
  if (!artifact) {
    await recordFailure()
    return undefined
  }
  const payload = payloadOf(artifact)
  const client = await config.adapter.clients.find(artifact.clientId)
  return client ? { artifact, payload, client } : undefined
}

export const resolveDeviceCode = async (
  config: ResolvedConfig,
  typed: string,
  outcome: DeviceApproval | { denied: true },
  context: UserCodeContext = {}
) => {
  const found = await findByUserCode(config, typed, context)
  if (!found) throw new OAuthError('invalid_request', { description: 'that code is not one we are waiting for', status: 404 })
  if (found.payload.status !== 'pending') {
    throw new OAuthError('invalid_request', { description: 'that code has already been answered', status: 409 })
  }

  if ('denied' in outcome) {
    const payload = { ...found.payload, status: 'denied' as const }
    await config.adapter.artifacts.upsert({ ...found.artifact, payload: payload as unknown as Record<string, unknown> })
    return { approved: false as const, client: found.client }
  }

  const scopes = await checkApproval(config, found.payload.scopes, outcome)
  const previous = await config.adapter.grants.findByAccountAndClient(outcome.accountId, found.artifact.clientId)
  const grant = {
    id: previous?.id ?? randomString(),
    accountId: outcome.accountId,
    clientId: found.artifact.clientId,
    scopes: [...new Set([...(previous?.scopes ?? []), ...scopes])],
    claims: previous?.claims ?? [],
    resources: previous?.resources ?? {},
    createdAt: previous?.createdAt ?? new Date()
  }
  await config.adapter.grants.upsert(grant)

  const payload = {
    ...found.payload,
    scopes,
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

export const deviceCodeGrant = async (config: ResolvedConfig, client: Client, form: URLSearchParams, binding: Binding) => {
  const deviceCode = form.get('device_code')
  if (!deviceCode) throw new OAuthError('invalid_request', { description: 'device_code is required' })

  const { payload } = await consumeDeviceCode(config, deviceCode, client.clientId)
  if (!payload.grantId || !payload.sessionId) throw new OAuthError('invalid_grant', { description: 'this device code was never approved' })

  const grant = await config.adapter.grants.find(payload.grantId)
  const session = await config.adapter.sessions.find(payload.sessionId)
  if (!grant || !session) throw new OAuthError('invalid_grant', { description: 'the grant or session behind this device code is gone' })

  return issueTokens(config, client, grant, session, payload.scopes, { binding })
}
