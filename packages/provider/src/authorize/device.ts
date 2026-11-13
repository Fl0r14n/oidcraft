import type { Client } from '@oidcraft/adapter'
import { randomString } from '@oidcraft/core'
import { authenticateClient } from '../clients/authenticate'
import type { ResolvedConfig } from '../config'
import type { ClientCertificate, RequestContext } from '../context'
import { OAuthError } from '../errors'
import { readForm } from '../form'
import { readArtifact, readByUserCode, type Stored, writeArtifact } from '../payloads'
import { bindBrowser } from '../session/browser'
import type { Binding } from '../token/issue'
import { type Approval, answer, answered, DEFAULT_INTERVAL, type Flow, type Polled, redeem } from './decoupled'

// RFC 8628 §6.1: base32 without what is misread or misheard: no 0/O, 1/I/L, or U (heard as V).
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

export const DEVICE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code'

export const deviceAuthorizationEndpoint = async (
  config: ResolvedConfig,
  request: Request,
  certificate?: ClientCertificate | undefined
) => {
  const form = await readForm(request)
  const { client } = await authenticateClient(config, form, request.headers, certificate)
  if (!client.grantTypes.includes(DEVICE_GRANT)) {
    throw new OAuthError('unauthorized_client', {
      description: `client ${client.clientId} is not registered for the device grant`,
      spec: 'RFC 8628 §3.1'
    })
  }

  const scopes = (form.get('scope') ?? 'openid').split(' ').filter(Boolean)
  const unallowed = scopes.filter(scope => !client.scopes.includes(scope))
  if (unallowed.length)
    throw new OAuthError('invalid_scope', {
      description: `client ${client.clientId} may not request: ${unallowed.join(', ')}`,
      spec: 'RFC 6749 §3.3'
    })

  const deviceCode = randomString()
  const code = userCode()
  const expiresIn = config.ttl.deviceCode
  const expiresAt = new Date(Date.now() + expiresIn * 1000)

  await writeArtifact(config.adapter.artifacts, {
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

export type DevicePayload = Polled & { userCode: string }

// The answer is its own record (NFR-S11), so a poll cannot undo it (FR-C7); never with `userCode`, which adapters index.
const deviceFlow: Flow<Stored<'device_code'>, DevicePayload> = {
  kind: 'device_code',
  noun: 'device code',
  spec: 'RFC 8628 §3.5',
  async load(config, id) {
    const request = await readArtifact(config.adapter.artifacts, 'device_code', id)
    return request && { request, requested: request.payload }
  },
  keepClock: (config, request, polled) => writeArtifact(config.adapter.artifacts, { ...request, payload: polled }),
  readAnswer: async (config, _request, requested) =>
    (await readArtifact(config.adapter.artifacts, 'user_code', requested.userCode))?.payload,
  writeAnswer: (config, request, requested, answer) =>
    writeArtifact(config.adapter.artifacts, {
      id: requested.userCode,
      kind: 'user_code',
      clientId: request.clientId,
      ...(answer.accountId && { accountId: answer.accountId }),
      payload: answer,
      expiresAt: request.expiresAt
    }),
  destroyAnswer: (config, _request, requested) => config.adapter.artifacts.destroy('user_code', requested.userCode)
}

export type DeviceApproval = Exclude<Approval, { denied: true }>

const ATTEMPT_WINDOW_SECONDS = 600
const MAX_FAILURES = 5
// Without a peer address every guesser shares one bucket, so it is wider, or one person locks out all.
const MAX_ANONYMOUS_FAILURES = 50

/** Who is typing codes, as far as the host can tell. Only the peer address counts (FR-R4). */
export type UserCodeContext = Pick<RequestContext, 'clientIp'>

// RFC 8628 §5.1: wrong guesses are limited per peer, by a read-then-write count that bounds guessing, not an exact quota.
const attemptsFor = async (config: ResolvedConfig, context: UserCodeContext) => {
  const id = context.clientIp ? `ip:${context.clientIp}` : 'anonymous'
  const limit = context.clientIp ? MAX_FAILURES : MAX_ANONYMOUS_FAILURES
  const record = await readArtifact(config.adapter.artifacts, 'user_code_attempts', id)
  const failures = record?.payload.failures ?? 0
  if (failures >= limit) {
    throw new OAuthError('invalid_request', { description: 'too many wrong codes; try again later', spec: 'RFC 8628 §5.1', status: 429 })
  }
  return async () => {
    await writeArtifact(config.adapter.artifacts, {
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
  const artifact = await readByUserCode(config.adapter.artifacts, normalizeUserCode(typed))
  if (!artifact) {
    await recordFailure()
    return undefined
  }
  const payload = await answered(config, deviceFlow, artifact, artifact.payload)
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
  if (!found)
    throw new OAuthError('invalid_request', { description: 'that code is not one we are waiting for', status: 404, spec: 'FR-C7' })
  if (found.payload.status !== 'pending') {
    throw new OAuthError('invalid_request', { description: 'that code has already been answered', status: 409, spec: 'FR-C7' })
  }

  const approved = await answer(config, deviceFlow, found.artifact, found.artifact.payload, outcome)
  return { approved, client: found.client }
}

/** A verification page has no authorization request to suspend, so this is the login interaction it lacks (FR-C7). */
export type DeviceSignInContext = UserCodeContext & { cookie: string | null }

export const deviceSignIn = async (config: ResolvedConfig, typed: string, { cookie, ...context }: DeviceSignInContext) => {
  const found = await findByUserCode(config, typed, context)
  if (found?.payload.status !== 'pending') {
    throw new OAuthError('invalid_request', { description: 'that code is not one we are waiting for', status: 404, spec: 'FR-C7' })
  }
  const id = randomString()
  const { browser, setCookie } = await bindBrowser(config, cookie)
  await writeArtifact(config.adapter.artifacts, {
    id,
    kind: 'interaction',
    clientId: found.artifact.clientId,
    payload: { interactionKind: 'login', browser, device: { userCode: found.payload.userCode, scopes: found.payload.scopes } },
    expiresAt: new Date(Math.min(Date.now() + config.ttl.interaction * 1000, found.artifact.expiresAt.getTime()))
  })
  return { redirectTo: `${config.interactionUrl}/${id}`, setCookie }
}

export const deviceCodeGrant = async (config: ResolvedConfig, client: Client, form: URLSearchParams, binding: Binding) => {
  const deviceCode = form.get('device_code')
  if (!deviceCode) throw new OAuthError('invalid_request', { description: 'device_code is required', spec: 'RFC 8628 §3.4' })
  return redeem(config, deviceFlow, deviceCode, client, binding)
}
