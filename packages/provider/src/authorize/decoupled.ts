import type { Artifact, Client } from '@oidcraft/adapter'
import { randomString } from '@oidcraft/core'
import type { ResolvedConfig } from '../config'
import { OAuthError } from '../errors'
import { type Binding, issueTokens } from '../token/issue'
import { checkApproval } from './approval'
import { recordConsent } from './consent'

export const DEFAULT_INTERVAL = 5

/** The person's answer. It is a record of its own, never written into the request a poll rewrites (FR-C7). */
export type Answer = {
  status: 'pending' | 'approved' | 'denied'
  scopes: string[]
  accountId?: string
  sessionId?: string
  grantId?: string
}

/** A request as the poll holds it: the clock the client is kept to, and what an answer fills in. */
export type Polled = Answer & { interval: number; lastPolledAt?: number }

type Request = Omit<Artifact, 'kind' | 'payload'>

/**
 * Device authorization and CIBA are one state machine: a client polls a request a person answers
 * somewhere else (RFC 8628 §3.5, OIDC CIBA 1.0 §11). A flow names only where its request and its
 * answer are kept, and what to call them.
 */
export type Flow<R extends Request, P extends Polled> = {
  kind: 'device_code' | 'backchannel_authentication_request'
  /** As the client knows it, for error descriptions. */
  noun: string
  spec: string
  load(config: ResolvedConfig, id: string): Promise<{ request: R; requested: P } | undefined>
  keepClock(config: ResolvedConfig, request: R, polled: P): Promise<void>
  readAnswer(config: ResolvedConfig, request: R, requested: P): Promise<Answer | undefined>
  writeAnswer(config: ResolvedConfig, request: R, requested: P, answer: Answer): Promise<void>
  destroyAnswer(config: ResolvedConfig, request: R, requested: P): Promise<void>
}

export const answered = async <R extends Request, P extends Polled>(
  config: ResolvedConfig,
  flow: Flow<R, P>,
  request: R,
  requested: P
) => ({
  ...requested,
  ...(await flow.readAnswer(config, request, requested))
})

/** Slow-down is enforced, not trusted to the client: one that ignores `interval` is the one to limit. */
const poll = async <R extends Request, P extends Polled>(config: ResolvedConfig, flow: Flow<R, P>, id: string, clientId: string) => {
  const refuse = (code: 'invalid_grant' | 'expired_token', description: string) => new OAuthError(code, { description, spec: flow.spec })
  const found = await flow.load(config, id)
  if (!found) throw refuse('expired_token', `this ${flow.noun} is unknown or expired`)
  const { request, requested } = found
  if (request.clientId !== clientId) throw refuse('invalid_grant', `this ${flow.noun} belongs to another client`)
  if (request.consumedAt) throw refuse('invalid_grant', `this ${flow.noun} was already redeemed`)

  const now = Date.now()
  const since = requested.lastPolledAt ? (now - requested.lastPolledAt) / 1000 : Number.POSITIVE_INFINITY
  const slowDown = since < requested.interval
  const interval = requested.interval + (slowDown ? DEFAULT_INTERVAL : 0)
  await flow.keepClock(config, request, { ...requested, lastPolledAt: now, interval })
  if (slowDown) throw new OAuthError('slow_down', { description: `poll no more often than every ${interval} seconds`, spec: flow.spec })

  const payload = await answered(config, flow, request, requested)
  if (payload.status === 'denied') throw new OAuthError('access_denied', { description: 'the user declined', spec: flow.spec })
  if (payload.status === 'pending')
    throw new OAuthError('authorization_pending', { description: 'the user has not answered yet', spec: flow.spec })

  // Single-use: an approval redeems once, however many times the client polls (NFR-S4).
  if (!(await config.adapter.artifacts.consume(flow.kind, id))) throw refuse('invalid_grant', `this ${flow.noun} was already redeemed`)
  await config.adapter.artifacts.destroy(flow.kind, id)
  await flow.destroyAnswer(config, request, requested)
  return payload
}

/** The token request a polling client makes, ping clients included (OIDC CIBA 1.0 §10.2). */
export const redeem = async <R extends Request, P extends Polled>(
  config: ResolvedConfig,
  flow: Flow<R, P>,
  id: string,
  client: Client,
  binding: Binding
) => {
  const payload = await poll(config, flow, id, client.clientId)
  if (!payload.grantId || !payload.sessionId)
    throw new OAuthError('invalid_grant', { description: `this ${flow.noun} was never approved`, spec: flow.spec })
  const grant = await config.adapter.grants.find(payload.grantId)
  const session = await config.adapter.sessions.find(payload.sessionId)
  if (!grant || !session)
    throw new OAuthError('invalid_grant', { description: `the grant or session behind this ${flow.noun} is gone`, spec: flow.spec })
  return issueTokens(config, client, grant, session, payload.scopes, { familyId: randomString(), binding })
}

export type Approval = { accountId: string; sessionId: string; scopes: string[] } | { denied: true }

/**
 * Records the person's answer to a pending request: every scope asked or `{ denied: true }`, as in
 * the browser (FR-I4). The approving session takes the client onto its list now, so ending it
 * reaches the client that is about to hold its tokens (FR-C11).
 */
export const answer = async <R extends Request, P extends Polled>(
  config: ResolvedConfig,
  flow: Flow<R, P>,
  request: R,
  requested: P,
  outcome: Approval,
  expectedAccountId?: string | undefined
) => {
  if ('denied' in outcome) {
    await flow.writeAnswer(config, request, requested, { status: 'denied', scopes: requested.scopes })
    return false
  }
  const scopes = await checkApproval(config, requested.scopes, outcome, expectedAccountId)
  await config.adapter.sessions.addClient(outcome.sessionId, request.clientId)
  const grant = await recordConsent(config, outcome.accountId, request.clientId, scopes)
  await flow.writeAnswer(config, request, requested, {
    status: 'approved',
    scopes,
    accountId: outcome.accountId,
    sessionId: outcome.sessionId,
    grantId: grant.id
  })
  return true
}
