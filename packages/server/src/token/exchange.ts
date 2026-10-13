import { randomString } from '@oidcraft/core'
import type { ResolvedConfig } from '../config'
import { OAuthError } from '../errors'
import type { Artifact, ArtifactKind, Client } from '../types'
import { findPresented } from './access-token'
import { type Binding, confirmationOf } from './issue'
import { subjectFor } from './subjects'

export const TOKEN_EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange'

const ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token'
const REFRESH_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:refresh_token'

/** What this exchange issues. An ID token is not stored, so it can be neither issued nor accepted here. */
export const SUPPORTED_TOKEN_TYPES = [ACCESS_TOKEN_TYPE]

const KIND_OF: Record<string, ArtifactKind> = { [ACCESS_TOKEN_TYPE]: 'access_token', [REFRESH_TOKEN_TYPE]: 'refresh_token' }

export type ExchangeDecision = {
  /** The account the new token speaks for. Impersonation keeps it; delegation may not. */
  accountId: string
  scopes: string[]
  /** The party acting on the subject's behalf, recorded as `act` (RFC 8693 §4.1). */
  actor?: { clientId: string } | undefined
  resource?: string | undefined
  audience?: string | undefined
}

export type ExchangePolicy = (input: {
  config: ResolvedConfig
  client: Client
  subjectToken: Artifact
  actorToken: Artifact | undefined
  requested: { scopes: string[]; resource: string | undefined; audience: string | undefined; tokenType: string }
}) => Promise<ExchangeDecision | undefined> | ExchangeDecision | undefined

/** RFC 8693 §2.1: the declared type says what the token is, so it is looked up as that and nothing else. */
const resolveToken = async (config: ResolvedConfig, value: string, declaredType: string | null, parameter: string) => {
  const kind = declaredType ? KIND_OF[declaredType] : undefined
  if (!kind) {
    throw new OAuthError('invalid_request', {
      description: `${parameter}_type must be the access_token or refresh_token type`,
      spec: 'RFC 8693 §3'
    })
  }
  const artifact = await findPresented(config, kind, value)
  return artifact && !artifact.consumedAt ? artifact : undefined
}

/**
 * Token exchange (RFC 8693).
 *
 * There is no sensible default policy here, so there is none: without an `exchangePolicy` the grant
 * is refused. Exchange is how one party asks to act as another, and a library cannot know which of
 * those requests a deployment considers legitimate — guessing would mean inventing an authorization
 * rule on the operator's behalf.
 */
export const tokenExchange = async (config: ResolvedConfig, client: Client, form: URLSearchParams) => {
  if (!config.exchangePolicy) {
    throw new OAuthError('unsupported_grant_type', {
      description: 'token exchange needs an exchangePolicy; the provider will not decide who may act as whom',
      spec: 'RFC 8693 §2.1'
    })
  }

  const subjectToken = form.get('subject_token')
  if (!subjectToken) throw new OAuthError('invalid_request', { description: 'subject_token is required', spec: 'RFC 8693 §2.1' })

  const subjectTokenType = form.get('subject_token_type')
  if (!subjectTokenType) throw new OAuthError('invalid_request', { description: 'subject_token_type is required', spec: 'RFC 8693 §2.1' })

  const requestedType = form.get('requested_token_type') ?? ACCESS_TOKEN_TYPE
  if (!SUPPORTED_TOKEN_TYPES.includes(requestedType)) {
    throw new OAuthError('invalid_request', { description: `requested_token_type ${requestedType} is not supported` })
  }

  const subject = await resolveToken(config, subjectToken, subjectTokenType, 'subject_token')
  if (!subject) throw new OAuthError('invalid_grant', { description: 'the subject_token is unknown or expired' })

  const actorTokenValue = form.get('actor_token')
  if (actorTokenValue && !form.get('actor_token_type')) {
    throw new OAuthError('invalid_request', {
      description: 'actor_token_type is required when actor_token is present',
      spec: 'RFC 8693 §2.1'
    })
  }
  const actor = actorTokenValue ? await resolveToken(config, actorTokenValue, form.get('actor_token_type'), 'actor_token') : undefined
  if (actorTokenValue && !actor) throw new OAuthError('invalid_grant', { description: 'the actor_token is unknown or expired' })

  const requestedScopes = (form.get('scope') ?? '').split(' ').filter(Boolean)
  const decision = await config.exchangePolicy({
    config,
    client,
    subjectToken: subject,
    actorToken: actor,
    requested: {
      scopes: requestedScopes,
      resource: form.get('resource') ?? undefined,
      audience: form.get('audience') ?? undefined,
      tokenType: requestedType
    }
  })

  if (!decision) throw new OAuthError('invalid_target', { description: 'this exchange was refused', spec: 'RFC 8693 §2.2.2' })

  // RFC 8693 §2.1: a widening beyond what the subject token held is an escalation, not an exchange.
  const held = (subject.payload.scopes as string[] | undefined) ?? []
  const widened = decision.scopes.filter((scope: string) => !held.includes(scope))
  if (widened.length) {
    throw new OAuthError('invalid_scope', { description: `an exchange cannot add scopes beyond the subject token: ${widened.join(', ')}` })
  }

  return { decision, requestedType, subject }
}

export const exchangeGrant = async (config: ResolvedConfig, client: Client, form: URLSearchParams, binding: Binding) => {
  const cnf = confirmationOf(binding)
  const { decision, subject } = await tokenExchange(config, client, form)

  // A sender-constrained token is only usable by its holder; exchanging it must not launder that away.
  const bound = subject.payload.cnf as { jkt?: string; 'x5t#S256'?: string } | undefined
  if ((bound?.jkt && bound.jkt !== binding.jkt) || (bound?.['x5t#S256'] && bound['x5t#S256'] !== binding.x5t)) {
    throw new OAuthError('invalid_grant', { description: 'the subject_token is bound to a key or certificate this request did not prove' })
  }

  const accessToken = randomString()
  // An exchanged token never outlives the one it was exchanged for.
  const expiresAt = new Date(Math.min(Date.now() + config.ttl.accessToken * 1000, subject.expiresAt.getTime()))
  const expiresIn = Math.max(0, Math.floor((expiresAt.getTime() - Date.now()) / 1000))
  await config.adapter.artifacts.upsert({
    id: accessToken,
    kind: 'access_token',
    clientId: client.clientId,
    accountId: decision.accountId,
    ...(subject.grantId && { grantId: subject.grantId }),
    payload: {
      scopes: decision.scopes,
      sessionId: subject.payload.sessionId as string,
      subject: await subjectFor(config, client, decision.accountId),
      // RFC 8693 §4.1: who is acting, so a resource server can tell delegation from the real thing.
      ...(decision.actor && { act: { client_id: decision.actor.clientId } }),
      ...(decision.resource && { resource: decision.resource }),
      ...(decision.audience && { aud: decision.audience }),
      ...(cnf && { cnf })
    },
    expiresAt
  })

  return {
    access_token: accessToken,
    issued_token_type: ACCESS_TOKEN_TYPE,
    token_type: binding.jkt ? 'DPoP' : 'Bearer',
    expires_in: expiresIn,
    scope: decision.scopes.join(' ')
  }
}
