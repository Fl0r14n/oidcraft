import type { ResolvedConfig } from '../config'
import { OAuthError } from '../errors'
import type { Artifact, ArtifactKind, Client } from '../types'

export const TOKEN_EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange'

const ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token'
const ID_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:id_token'
const REFRESH_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:refresh_token'

export const SUPPORTED_TOKEN_TYPES = [ACCESS_TOKEN_TYPE, ID_TOKEN_TYPE]

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

const resolveToken = async (config: ResolvedConfig, value: string, declaredType: string | null) => {
  const kinds: ArtifactKind[] =
    declaredType === REFRESH_TOKEN_TYPE
      ? ['refresh_token']
      : declaredType === ID_TOKEN_TYPE
        ? ['access_token']
        : ['access_token', 'refresh_token']
  for (const kind of kinds) {
    const artifact = await config.adapter.artifacts.find(kind, value)
    if (artifact && !artifact.consumedAt) return artifact
  }
  return undefined
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

  const subject = await resolveToken(config, subjectToken, subjectTokenType)
  if (!subject) throw new OAuthError('invalid_grant', { description: 'the subject_token is unknown or expired' })

  const actorTokenValue = form.get('actor_token')
  if (actorTokenValue && !form.get('actor_token_type')) {
    throw new OAuthError('invalid_request', {
      description: 'actor_token_type is required when actor_token is present',
      spec: 'RFC 8693 §2.1'
    })
  }
  const actor = actorTokenValue ? await resolveToken(config, actorTokenValue, form.get('actor_token_type')) : undefined
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
