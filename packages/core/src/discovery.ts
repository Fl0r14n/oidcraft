import { resolveOAuthFunctions } from './functions'
import { InsecureEndpointError, isTenantTemplate, sameIssuer } from './secure'
import type { Discovery, OAuthFunctions, OpenIdConfig, OpenIdConfiguration } from './types'

/** The discovery document asserts an issuer other than the one it was fetched from: a configuration fault, not an outage. */
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

/** Endpoints configured statically win; discovery is the fallback. */
export const needsDiscovery = (config?: Partial<OpenIdConfig>) => {
  const { tokenPath, authorizePath } = (config || {}) as OpenIdConfig
  return !(tokenPath || authorizePath)
}

// OIDC Discovery 1.0 §4.3; Entra's `{tenantid}` template is the one exception, resolved per token in `jwt.ts`.
const assertIssuer = (issuerPath: string | undefined, discovered: OpenIdConfiguration) => {
  if (!issuerPath || !discovered.issuer) return
  if (isTenantTemplate(discovered.issuer)) return
  if (!sameIssuer(discovered.issuer, issuerPath)) throw new IssuerMismatchError(issuerPath, discovered.issuer)
}

/** Maps the well-known document onto the config; an absent member leaves a static value in place. */
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

/** An issuer-keyed discovery cache, so a process fetches each well-known document once; a failed lookup is not cached. */
export const createDiscovery = ({ functions }: { functions?: Partial<OAuthFunctions> } = {}): Discovery => {
  const cache = new Map<string, Promise<OpenIdConfiguration | undefined>>()
  return async (config?: Partial<OpenIdConfig>) => {
    const key = `${(config as OpenIdConfig)?.issuerPath}|${config?.clientId || ''}`
    let discovered = cache.get(key)
    if (!discovered) {
      // a user-supplied `openIdConfiguration` may return a bare value rather than a promise
      discovered = Promise.resolve(resolveOAuthFunctions(functions).openIdConfiguration(config))
      cache.set(key, discovered)
    }
    const result = await discovered.catch(error => {
      cache.delete(key)
      // A refused http issuer is the configuration, not an outage: swallowed, it surfaces as a missing endpoint.
      if (error instanceof InsecureEndpointError) throw error
      return undefined
    })
    if (!result) {
      cache.delete(key)
    }
    return result
  }
}
