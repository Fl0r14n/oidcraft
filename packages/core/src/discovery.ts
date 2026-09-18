import { resolveOAuthFunctions } from './functions'
import { isTenantTemplate, sameIssuer } from './secure'
import type { Discovery, OAuthFunctions, OpenIdConfig, OpenIdConfiguration } from './types'

/** Same class as `InsecureEndpointError`: the document is not trustworthy, and that is a fact about
 * the configuration rather than a request that happened not to work. */
export class IssuerMismatchError extends Error {
  readonly expected: string
  readonly actual: string

  constructor(expected: string, actual: string) {
    super(`the document at ${expected} claims to be issued by ${actual}; one of the two is not the provider you think it is`)
    this.name = 'IssuerMismatchError'
    this.expected = expected
    this.actual = actual
  }
}

/** Endpoints already configured statically win — discovery is the fallback, not the source of truth. */
export const needsDiscovery = (config?: Partial<OpenIdConfig>) => {
  const { tokenPath, authorizePath } = (config || {}) as OpenIdConfig
  return !(tokenPath || authorizePath)
}

/**
 * OIDC Discovery 1.0 §4.3: the `issuer` the document asserts must be the URL it was fetched from.
 * Without this check a provider that will happily serve a document for someone else's issuer — a
 * multi-tenant host, an open redirect, a misrouted proxy — hands over that issuer's endpoints.
 *
 * Entra's multi-tenant document is the one documented exception: it advertises a `{tenantid}`
 * template because the tenant is not known until a token arrives, so it can never match literally
 * and the id-token verifier resolves it per token instead (`jwt.ts`).
 */
const assertIssuer = (issuerPath: string | undefined, discovered: OpenIdConfiguration) => {
  if (!issuerPath || !discovered.issuer) return
  if (isTenantTemplate(discovered.issuer)) return
  if (!sameIssuer(discovered.issuer, issuerPath)) throw new IssuerMismatchError(issuerPath, discovered.issuer)
}

/** The well-known document mapped onto the config's own names. Absent members leave the config's value
 * alone, so a static override survives a later discovery. */
export const applyDiscovery = (config: Partial<OpenIdConfig> | undefined, discovered?: OpenIdConfiguration) => {
  const c = (config || {}) as OpenIdConfig
  if (!discovered) return c
  assertIssuer(c?.issuerPath, discovered)
  return {
    ...c,
    ...(discovered.issuer && { issuer: discovered.issuer }),
    ...(discovered.authorization_endpoint && { authorizePath: discovered.authorization_endpoint }),
    ...(discovered.token_endpoint && { tokenPath: discovered.token_endpoint }),
    ...(discovered.revocation_endpoint && { revokePath: discovered.revocation_endpoint }),
    ...(discovered.userinfo_endpoint && { userPath: discovered.userinfo_endpoint }),
    ...(discovered.introspection_endpoint && { introspectionPath: discovered.introspection_endpoint }),
    ...(discovered.end_session_endpoint && { logoutPath: discovered.end_session_endpoint }),
    ...(discovered.jwks_uri && { jwksUri: discovered.jwks_uri }),
    // RFC 9207: a provider that advertises it is a provider whose silence on `iss` is an error.
    ...(discovered.authorization_response_iss_parameter_supported !== undefined && {
      issuerParameter: discovered.authorization_response_iss_parameter_supported
    }),
    ...(c?.pkce === undefined &&
      discovered.code_challenge_methods_supported && { pkce: discovered.code_challenge_methods_supported.indexOf('S256') > -1 }),
    scope: c?.scope || 'openid'
  }
}

/** An issuer-keyed lookup, so a process serving many requests fetches each well-known document once.
 * A failed lookup is not cached — a transient outage would otherwise stick for the process lifetime. */
export const createDiscovery = ({ functions }: { functions?: Partial<OAuthFunctions> } = {}): Discovery => {
  const cache = new Map<string, Promise<OpenIdConfiguration | undefined>>()
  return async (config?: Partial<OpenIdConfig>) => {
    const key = `${(config as OpenIdConfig)?.issuerPath}|${config?.clientId || ''}`
    let discovered = cache.get(key)
    if (!discovered) {
      // wrapped, not assumed: `functions` is a user-supplied partial, and one whose
      // `openIdConfiguration` returns a bare value rather than a promise would otherwise crash the
      // cache rather than simply not discover anything
      discovered = Promise.resolve(resolveOAuthFunctions(functions).openIdConfiguration(config))
      cache.set(key, discovered)
    }
    const result = await discovered.catch(() => undefined)
    if (!result) {
      cache.delete(key)
    }
    return result
  }
}
