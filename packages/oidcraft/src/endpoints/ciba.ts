import { authenticateClient } from '../client-auth'
import type { ResolvedConfig } from '../config'
import { OAuthError } from '../errors'
import { token } from '../random'
import type { Artifact } from '../types'

export const CIBA_GRANT = 'urn:openid:params:grant-type:ciba'

const DEFAULT_INTERVAL = 5

export type CibaPayload = {
  scopes: string[]
  status: 'pending' | 'approved' | 'denied'
  interval: number
  mode: 'poll' | 'ping'
  bindingMessage?: string
  clientNotificationToken?: string
  accountId?: string
  sessionId?: string
  grantId?: string
  lastPolledAt?: number
}

const payloadOf = (artifact: Artifact) => artifact.payload as unknown as CibaPayload

/**
 * Client-Initiated Backchannel Authentication.
 *
 * The defining property is that the client never touches the user's browser: it names who it wants
 * and the provider reaches them out of band. That makes identifying the user the provider's problem
 * entirely, which is why `resolveCibaUser` has no default — a library guessing which `login_hint`
 * means which account would be inventing an authentication decision.
 */
export const backchannelAuthenticationEndpoint = async (config: ResolvedConfig, request: Request) => {
  const form = new URLSearchParams(await request.text())
  const { client } = await authenticateClient(config, form, request.headers)

  if (!config.resolveCibaUser) {
    throw new OAuthError('unsupported_grant_type', {
      description: 'CIBA needs a resolveCibaUser; the provider will not guess which hint means which account',
      spec: 'OIDC CIBA 1.0 §7.1'
    })
  }

  const hints = ['login_hint', 'login_hint_token', 'id_token_hint'].filter(name => form.has(name))
  // OIDC CIBA 1.0 §7.1: more than one hint is ambiguous, and resolving it by precedence would let a
  // caller make the provider and an auditor disagree about who was asked.
  if (hints.length !== 1) {
    throw new OAuthError('invalid_request', {
      description: hints.length === 0 ? 'one of login_hint, login_hint_token or id_token_hint is required' : 'only one hint may be given',
      spec: 'OIDC CIBA 1.0 §7.1'
    })
  }

  const mode = client.backchannelTokenDeliveryMode ?? 'poll'
  const notificationToken = form.get('client_notification_token')
  if (mode === 'ping' && !notificationToken) {
    throw new OAuthError('invalid_request', {
      description: 'client_notification_token is required in ping mode',
      spec: 'OIDC CIBA 1.0 §7.1'
    })
  }

  const scopes = (form.get('scope') ?? 'openid').split(' ').filter(Boolean)
  if (!scopes.includes('openid')) throw new OAuthError('invalid_scope', { description: 'scope must include openid' })
  const unallowed = scopes.filter(scope => !client.scopes.includes(scope))
  if (unallowed.length)
    throw new OAuthError('invalid_scope', { description: `client ${client.clientId} may not request: ${unallowed.join(', ')}` })

  const resolved = await config.resolveCibaUser({
    client,
    hint: { kind: hints[0] as string, value: form.get(hints[0] as string) as string },
    scopes,
    bindingMessage: form.get('binding_message') ?? undefined
  })
  if (!resolved) throw new OAuthError('unknown_user_id', { description: 'no user matches that hint', spec: 'OIDC CIBA 1.0 §13' })

  const authReqId = token()
  const expiresIn = config.ttl.backchannelRequest
  await config.adapter.artifacts.upsert({
    id: authReqId,
    kind: 'backchannel_authentication_request',
    clientId: client.clientId,
    accountId: resolved.accountId,
    payload: {
      scopes,
      status: 'pending',
      interval: DEFAULT_INTERVAL,
      mode,
      ...(form.get('binding_message') && { bindingMessage: form.get('binding_message') }),
      ...(notificationToken && { clientNotificationToken: notificationToken })
    },
    expiresAt: new Date(Date.now() + expiresIn * 1000)
  })

  return Response.json(
    { auth_req_id: authReqId, expires_in: expiresIn, ...(mode === 'poll' && { interval: DEFAULT_INTERVAL }) },
    { status: 200, headers: { 'cache-control': 'no-store', pragma: 'no-cache' } }
  )
}

/** The same slow-down discipline as the device flow: the provider enforces it (OIDC CIBA 1.0 §11). */
export const consumeAuthReqId = async (config: ResolvedConfig, authReqId: string, clientId: string) => {
  const artifact = await config.adapter.artifacts.find('backchannel_authentication_request', authReqId)
  if (!artifact) throw new OAuthError('expired_token', { description: 'that auth_req_id is unknown or expired', spec: 'OIDC CIBA 1.0 §11' })
  if (artifact.clientId !== clientId) throw new OAuthError('invalid_grant', { description: 'that auth_req_id belongs to another client' })

  const payload = payloadOf(artifact)
  if (payload.mode !== 'poll') {
    throw new OAuthError('invalid_grant', { description: 'this request is delivered by ping; poll only after the notification' })
  }

  const now = Date.now()
  const since = payload.lastPolledAt ? (now - payload.lastPolledAt) / 1000 : Number.POSITIVE_INFINITY
  if (since < payload.interval) {
    payload.interval += DEFAULT_INTERVAL
    payload.lastPolledAt = now
    await config.adapter.artifacts.upsert({ ...artifact, payload: payload as unknown as Record<string, unknown> })
    throw new OAuthError('slow_down', {
      description: `poll no more often than every ${payload.interval} seconds`,
      spec: 'OIDC CIBA 1.0 §11'
    })
  }

  payload.lastPolledAt = now
  await config.adapter.artifacts.upsert({ ...artifact, payload: payload as unknown as Record<string, unknown> })

  if (payload.status === 'denied') throw new OAuthError('access_denied', { description: 'the user declined', spec: 'OIDC CIBA 1.0 §11' })
  if (payload.status === 'pending')
    throw new OAuthError('authorization_pending', { description: 'the user has not answered yet', spec: 'OIDC CIBA 1.0 §11' })

  await config.adapter.artifacts.destroy('backchannel_authentication_request', authReqId)
  return { artifact, payload }
}

export type CibaDecision = { accountId: string; sessionId: string; scopes: string[] } | { denied: true }

/** What the out-of-band channel calls once the person has answered on their own device. */
export const resolveBackchannelRequest = async (config: ResolvedConfig, authReqId: string, outcome: CibaDecision) => {
  const artifact = await config.adapter.artifacts.find('backchannel_authentication_request', authReqId)
  if (!artifact) throw new OAuthError('invalid_request', { description: 'that request is unknown or expired', status: 404 })
  const payload = payloadOf(artifact)
  if (payload.status !== 'pending')
    throw new OAuthError('invalid_request', { description: 'that request was already answered', status: 409 })

  if ('denied' in outcome) {
    await config.adapter.artifacts.upsert({
      ...artifact,
      payload: { ...payload, status: 'denied' } as unknown as Record<string, unknown>
    })
    return { approved: false as const, notify: payload.mode === 'ping' ? payload.clientNotificationToken : undefined }
  }

  const previous = await config.adapter.grants.findByAccountAndClient(outcome.accountId, artifact.clientId)
  const grant = {
    id: previous?.id ?? token(),
    accountId: outcome.accountId,
    clientId: artifact.clientId,
    scopes: [...new Set([...(previous?.scopes ?? []), ...outcome.scopes])],
    claims: previous?.claims ?? [],
    resources: previous?.resources ?? {},
    createdAt: previous?.createdAt ?? new Date()
  }
  await config.adapter.grants.upsert(grant)

  await config.adapter.artifacts.upsert({
    ...artifact,
    accountId: outcome.accountId,
    grantId: grant.id,
    payload: {
      ...payload,
      status: 'approved',
      accountId: outcome.accountId,
      sessionId: outcome.sessionId,
      grantId: grant.id
    } as unknown as Record<string, unknown>
  })

  return { approved: true as const, notify: payload.mode === 'ping' ? payload.clientNotificationToken : undefined }
}
