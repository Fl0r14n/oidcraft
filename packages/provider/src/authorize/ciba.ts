import type { Client } from '@oidcraft/adapter'
import { randomString } from '@oidcraft/core'
import { authenticateClient } from '../clients/authenticate'
import type { ResolvedConfig } from '../config'
import type { ClientCertificate } from '../context'
import { OAuthError } from '../errors'
import { readForm } from '../form'
import { readArtifact, type Stored, writeArtifact } from '../payloads'
import type { Binding } from '../token/issue'
import { answer, answered, DEFAULT_INTERVAL, type Flow, type Polled, redeem } from './decoupled'

export const CIBA_GRANT = 'urn:openid:params:grant-type:ciba'

export type CibaPayload = Polled & {
  mode: 'poll' | 'ping'
  bindingMessage?: string
  clientNotificationToken?: string
  notificationEndpoint?: string
}

const KIND = 'backchannel_authentication_request'

// The answer is its own record: a poll rewrites the request it read, losing any answer written into it (FR-C7).
const answerId = (authReqId: string) => `${authReqId}:answer`

const cibaFlow: Flow<Stored<typeof KIND>, CibaPayload> = {
  kind: KIND,
  noun: 'auth_req_id',
  spec: 'OIDC CIBA 1.0 §11',
  /** A request, never an answer: the answer's id is the request's with a suffix no presented id carries. */
  async load(config, id) {
    const request = await readArtifact(config.adapter.artifacts, KIND, id)
    return request && 'mode' in request.payload ? { request, requested: request.payload } : undefined
  },
  keepClock: (config, request, polled) => writeArtifact(config.adapter.artifacts, { ...request, payload: polled }),
  readAnswer: async (config, request) => (await readArtifact(config.adapter.artifacts, KIND, answerId(request.id)))?.payload,
  writeAnswer: (config, request, _requested, answer) =>
    writeArtifact(config.adapter.artifacts, {
      id: answerId(request.id),
      kind: KIND,
      clientId: request.clientId,
      ...(answer.accountId && { accountId: answer.accountId }),
      payload: answer,
      expiresAt: request.expiresAt
    }),
  destroyAnswer: (config, request) => config.adapter.artifacts.destroy(KIND, answerId(request.id))
}

// `resolveCibaUser` has no default: guessing which hint means which account would invent an authentication (FR-C17).
export const backchannelAuthenticationEndpoint = async (
  config: ResolvedConfig,
  request: Request,
  certificate?: ClientCertificate | undefined
) => {
  const form = await readForm(request)
  const { client } = await authenticateClient(config, form, request.headers, certificate)
  if (!client.grantTypes.includes(CIBA_GRANT)) {
    throw new OAuthError('unauthorized_client', {
      description: `client ${client.clientId} is not registered for the CIBA grant`,
      spec: 'OIDC CIBA 1.0 §13'
    })
  }

  if (!config.resolveCibaUser) {
    throw new OAuthError('unsupported_grant_type', {
      description: 'CIBA needs a resolveCibaUser; the provider will not guess which hint means which account',
      spec: 'OIDC CIBA 1.0 §7.1'
    })
  }

  const hints = ['login_hint', 'login_hint_token', 'id_token_hint'].filter(name => form.has(name))
  // OIDC CIBA 1.0 §7.1: exactly one hint, or precedence could make the provider and an auditor disagree on who was asked.
  if (hints.length !== 1) {
    throw new OAuthError('invalid_request', {
      description: hints.length === 0 ? 'one of login_hint, login_hint_token or id_token_hint is required' : 'only one hint may be given',
      spec: 'OIDC CIBA 1.0 §7.1'
    })
  }

  const mode = client.backchannelTokenDeliveryMode ?? 'poll'
  const notificationToken = form.get('client_notification_token')
  if (mode === 'ping' && !client.backchannelClientNotificationEndpoint) {
    throw new OAuthError('unauthorized_client', {
      description: `client ${client.clientId} is registered for ping but has no backchannel_client_notification_endpoint`,
      spec: 'OIDC CIBA 1.0 §4'
    })
  }
  if (mode === 'ping' && !notificationToken) {
    throw new OAuthError('invalid_request', {
      description: 'client_notification_token is required in ping mode',
      spec: 'OIDC CIBA 1.0 §7.1'
    })
  }

  const scopes = (form.get('scope') ?? 'openid').split(' ').filter(Boolean)
  if (!scopes.includes('openid'))
    throw new OAuthError('invalid_scope', { description: 'scope must include openid', spec: 'OIDC CIBA 1.0 §7.1' })
  const unallowed = scopes.filter(scope => !client.scopes.includes(scope))
  if (unallowed.length)
    throw new OAuthError('invalid_scope', {
      description: `client ${client.clientId} may not request: ${unallowed.join(', ')}`,
      spec: 'OIDC CIBA 1.0 §13'
    })

  const resolved = await config.resolveCibaUser({
    client,
    hint: { kind: hints[0] as string, value: form.get(hints[0] as string) as string },
    scopes,
    bindingMessage: form.get('binding_message') ?? undefined
  })
  if (!resolved) throw new OAuthError('unknown_user_id', { description: 'no user matches that hint', spec: 'OIDC CIBA 1.0 §13' })

  const authReqId = randomString()
  const expiresIn = config.ttl.backchannelRequest
  await writeArtifact(config.adapter.artifacts, {
    id: authReqId,
    kind: KIND,
    clientId: client.clientId,
    accountId: resolved.accountId,
    payload: {
      scopes,
      status: 'pending',
      interval: DEFAULT_INTERVAL,
      mode,
      ...(form.get('binding_message') && { bindingMessage: form.get('binding_message') }),
      ...(notificationToken && { clientNotificationToken: notificationToken }),
      // Fixed when the request is made, so re-registering mid-flight cannot redirect the ping.
      ...(mode === 'ping' && { notificationEndpoint: client.backchannelClientNotificationEndpoint })
    },
    expiresAt: new Date(Date.now() + expiresIn * 1000)
  })

  return Response.json(
    { auth_req_id: authReqId, expires_in: expiresIn, ...(mode === 'poll' && { interval: DEFAULT_INTERVAL }) },
    { status: 200, headers: { 'cache-control': 'no-store', pragma: 'no-cache' } }
  )
}

/**
 * A ping for the host to deliver (OIDC CIBA 1.0 §10.2): POST `{"auth_req_id": authReqId}` as JSON
 * to `uri`, with `Authorization: Bearer <clientNotificationToken>`. The core does no I/O (FR-A1).
 */
export type CibaPing = { clientId: string; uri: string; clientNotificationToken: string; authReqId: string }

const pingFor = (artifact: Stored<typeof KIND>, payload: CibaPayload): CibaPing | undefined =>
  payload.mode === 'ping' && payload.notificationEndpoint && payload.clientNotificationToken
    ? {
        clientId: artifact.clientId,
        uri: payload.notificationEndpoint,
        clientNotificationToken: payload.clientNotificationToken,
        authReqId: artifact.id
      }
    : undefined

export type CibaDecision = { accountId: string; sessionId: string; scopes: string[] } | { denied: true }

/** What the out-of-band channel calls once the person has answered on their own device. */
export const resolveBackchannelRequest = async (config: ResolvedConfig, authReqId: string, outcome: CibaDecision) => {
  const found = await cibaFlow.load(config, authReqId)
  if (!found) throw new OAuthError('invalid_request', { description: 'that request is unknown or expired', status: 404, spec: 'FR-C17' })
  const { request, requested } = found
  const payload = await answered(config, cibaFlow, request, requested)
  if (payload.status !== 'pending')
    throw new OAuthError('invalid_request', { description: 'that request was already answered', status: 409, spec: 'FR-C17' })

  // CIBA §7.1: the request named a user; an approval by anyone else is not an answer to it.
  const approved = await answer(config, cibaFlow, request, requested, outcome, request.accountId)
  // §10.2: a denial is pinged too; the client learns it from the token request that follows.
  return { approved, ping: pingFor(request, payload) }
}

export const cibaGrant = async (config: ResolvedConfig, client: Client, form: URLSearchParams, binding: Binding) => {
  const authReqId = form.get('auth_req_id')
  if (!authReqId) throw new OAuthError('invalid_request', { description: 'auth_req_id is required', spec: 'OIDC CIBA 1.0 §10.1' })
  return redeem(config, cibaFlow, authReqId, client, binding)
}
