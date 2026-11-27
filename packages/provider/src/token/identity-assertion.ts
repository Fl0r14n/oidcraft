import type { Client } from '@oidcraft/adapter'
import { createLocalJWKSet, decodeJwt, type JSONWebKeySet, type JWTPayload, jwtVerify } from 'jose'
import { audienceFor, requestedResources } from '../authorize/resources'
import type { ResolvedConfig } from '../config'
import { OAuthError } from '../errors'
import { CLIENT_SIGNING_ALGS } from '../keys/algorithms'
import { type Binding, issueAccessToken } from './access-token'
import { subjectFor } from './subjects'

export const JWT_BEARER_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:jwt-bearer'
export const ID_JAG_PROFILE = 'urn:ietf:params:oauth:grant-profile:id-jag'

const SPEC = 'draft-ietf-oauth-identity-assertion-authz-grant §4.4'
const TYPE = 'oauth-id-jag+jwt'
const SKEW = 60
const MAX_LIFETIME = 300
const DEFAULT_ALGORITHMS = ['RS256', 'ES256']

/** The issuer the host trusts an assertion from, and where its subjects are linked (FR-C24.1). */
export type TrustedIssuer = {
  /** Must equal the assertion's `iss` exactly, trailing slash and all. */
  issuer: string
  jwks: { keys: unknown[] }
  /** The upstream its subjects are linked under (FR-F5): the same as brokering's when the IdP is both. */
  upstream: string
  /** For a multi-tenant issuer, the tenant whose `tenant` claim an assertion must carry (§6.1). */
  tenant?: string
  /** Asymmetric only; a symmetric one listed here is ignored. `RS256` and `ES256` by default. */
  algorithms?: string[]
}

/**
 * Maps an assertion's unverified `iss`, `tenant` and `aud_tenant` to at most one trusted issuer (FR-C24.1).
 * Fetching its metadata and keys is yours (FR-A1). No default: any well-formed JWT would be sign-in as anyone.
 */
export type AssertionTrust = (input: {
  client: Client
  iss: string
  tenant: string | undefined
  aud_tenant: string | undefined
}) => TrustedIssuer | undefined | Promise<TrustedIssuer | undefined>

const refuse = (description: string, spec = `${SPEC}.1`) => new OAuthError('invalid_grant', { description, spec })

const optionalString = (payload: JWTPayload, claim: string) => {
  const value = payload[claim]
  if (value !== undefined && typeof value !== 'string') throw refuse(`${claim} must be a string`)
  return value
}

// FR-C24: createLocalJWKSet throws synchronously, so inlined into jwtVerify's call it would escape the catch as a 500.
const keysFrom = (trusted: TrustedIssuer) => {
  try {
    return createLocalJWKSet(trusted.jwks as JSONWebKeySet)
  } catch {
    throw refuse(`the keys trusted for ${trusted.issuer} are not a JWK Set`)
  }
}

const unverifiedClaims = (assertion: string) => {
  try {
    return decodeJwt(assertion)
  } catch {
    throw refuse('assertion is not a JWT')
  }
}

const resourcesFrom = (config: ResolvedConfig, payload: JWTPayload) => {
  const claimed = payload.resource
  const resources = claimed === undefined ? [] : typeof claimed === 'string' ? [claimed] : claimed
  if (!Array.isArray(resources) || resources.some(resource => typeof resource !== 'string')) {
    throw refuse('resource must be a string or an array of strings')
  }
  const unknown = (resources as string[]).filter(resource => !config.resources.some(candidate => candidate.uri === resource))
  if (unknown.length) throw refuse(`resource ${unknown.join(', ')} is not one this provider issues tokens for`)
  return resources as string[]
}

const scopesFor = (client: Client, payload: JWTPayload, form: URLSearchParams) => {
  // FR-C24.5: a scope claim read as absent would lift the IdP's limit, so one of the wrong shape is refused.
  if (payload.scope !== undefined && typeof payload.scope !== 'string') throw refuse('scope must be a space-separated string')
  const asserted = payload.scope?.split(' ').filter(Boolean)
  const requested = (form.get('scope') ?? '').split(' ').filter(Boolean)
  if (!requested.length) {
    return (asserted ?? client.scopes).filter(scope => client.scopes.includes(scope) && scope !== 'offline_access')
  }
  const beyond = requested.filter(
    scope => !client.scopes.includes(scope) || (asserted && !asserted.includes(scope)) || scope === 'offline_access'
  )
  if (beyond.length) {
    throw new OAuthError('invalid_scope', {
      description: `not granted by this assertion to client ${client.clientId}: ${beyond.join(', ')}`,
      spec: 'RFC 6749 §3.3'
    })
  }
  return requested
}

const verifyAssertion = async (config: ResolvedConfig, client: Client, assertion: string) => {
  const trust = config.assertionTrust
  if (!trust) throw new OAuthError('unsupported_grant_type', { description: 'identity assertions need an assertionTrust', spec: SPEC })

  const unverified = unverifiedClaims(assertion)
  const iss = optionalString(unverified, 'iss')
  if (!iss) throw refuse('iss is required')
  const trusted = await trust({
    client,
    iss,
    tenant: optionalString(unverified, 'tenant'),
    aud_tenant: optionalString(unverified, 'aud_tenant')
  })
  if (!trusted) throw refuse(`issuer ${iss} is not trusted here`)
  // FR-C24.1: the host's answer is checked too, so a trust keyed loosely cannot admit a neighbouring issuer.
  if (trusted.issuer !== iss) throw refuse(`issuer ${iss} is not the trusted ${trusted.issuer}`)

  // FR-C24.2: never HMAC, whatever the trust lists; a symmetric key in a published key set is a key anyone can sign with.
  const algorithms = (trusted.algorithms ?? DEFAULT_ALGORITHMS).filter(algorithm => CLIENT_SIGNING_ALGS.includes(algorithm))
  const { payload } = await jwtVerify(assertion, keysFrom(trusted), {
    issuer: iss,
    audience: config.issuer,
    algorithms,
    typ: TYPE,
    clockTolerance: SKEW,
    requiredClaims: ['sub', 'jti', 'iat', 'exp']
  }).catch(error => {
    throw refuse(`the assertion does not verify: ${error instanceof Error ? error.message : String(error)}`)
  })

  if (Array.isArray(payload.aud) && payload.aud.length !== 1) throw refuse('aud must name this issuer alone')
  if (typeof payload.sub !== 'string' || typeof payload.jti !== 'string') throw refuse('sub and jti must be strings')
  if (payload.client_id !== client.clientId) throw refuse(`the assertion was issued to another client than ${client.clientId}`)
  if (trusted.tenant !== undefined && payload.tenant !== trusted.tenant) throw refuse(`tenant must be ${trusted.tenant}`, `${SPEC}.1, §6.1`)
  if (payload.cnf !== undefined) throw refuse('a sender-constrained assertion is not supported here', `${SPEC}, §9.11`)
  const now = Math.floor(Date.now() / 1000)
  const iat = payload.iat as number
  const exp = payload.exp as number
  if (iat > now + SKEW) throw refuse('the assertion was issued in the future')
  if (exp - iat > MAX_LIFETIME) throw refuse(`an assertion may not live longer than ${MAX_LIFETIME} seconds`)
  return { payload, upstream: trusted.upstream }
}

// NFR-S5: per issuer, remembered while it would still verify; spent last, so a refused request can be retried.
const spend = async (config: ResolvedConfig, client: Client, payload: JWTPayload) => {
  const issuer = payload.iss as string
  const ttl = Math.max((payload.exp as number) - Math.floor(Date.now() / 1000), 0) + SKEW
  if (!(await config.adapter.replay.claim('identity-assertion', `${issuer} ${payload.jti}`, ttl))) {
    throw new OAuthError('invalid_grant', {
      description: 'this assertion was already used',
      spec: `${SPEC}.4`,
      event: { action: 'token.replay', clientId: client.clientId, detail: { kind: 'identity_assertion', issuer } }
    })
  }
}

// FR-C24.4: (upstream, sub) and nothing else; email and aud_sub are only the issuing tenant's word (§9.8, NFR-S8).
const accountFor = async (config: ResolvedConfig, upstream: string, subject: string) => {
  const linked = await config.adapter.identities?.find(upstream, subject)
  const account = linked && (await config.adapter.accounts.find(linked.accountId))
  if (!account) throw new OAuthError('access_denied', { description: 'no account here is linked to this subject', spec: `${SPEC}.3` })
  return account.accountId
}

// FR-C24.5: an access token only. No refresh token (§4.4.4) and no Grant, so no consent is remembered for a later sign-in.
export const redeemIdentityAssertion = async (config: ResolvedConfig, client: Client, form: URLSearchParams, binding: Binding) => {
  if (client.tokenEndpointAuthMethod === 'none') {
    throw new OAuthError('invalid_client', { description: 'an identity assertion is redeemed by a client that authenticates', spec: SPEC })
  }
  const assertion = form.get('assertion')
  if (!assertion) throw new OAuthError('invalid_request', { description: 'assertion is required', spec: 'RFC 7523 §2.1' })

  const { payload, upstream } = await verifyAssertion(config, client, assertion)
  const asserted = resourcesFrom(config, payload)
  const accountId = await accountFor(config, upstream, payload.sub as string)
  const scopes = scopesFor(client, payload, form)
  const audience = audienceFor(requestedResources(config, form, client.clientId), asserted)
  // Asked here as well as at issuance, which comes after the spend (FR-C19).
  if (audience !== undefined) requestedResources(config, new URLSearchParams({ resource: audience }), client.clientId)
  await spend(config, client, payload)

  const access = await issueAccessToken(config, {
    client,
    scopes,
    binding,
    accountId,
    subject: await subjectFor(config, client, accountId),
    audience
  })
  return { access_token: access.token, token_type: access.tokenType, expires_in: access.expiresIn, scope: scopes.join(' ') }
}
