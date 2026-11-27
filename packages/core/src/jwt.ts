import { createRemoteJWKSet, customFetch, decodeJwt, jwtVerify } from 'jose'
import { assertSecure, TENANT_TEMPLATE } from './secure'

export type IdTokenClaims = Record<string, any>

export type IdTokenVerifier = (idToken?: string) => Promise<IdTokenClaims>

/** A literal issuer, a set of them, or — when only the token says which — one derived from its claims. */
export type ExpectedIssuer = string | string[] | ((claims: IdTokenClaims) => string | undefined)

export type IdTokenVerifierOptions = {
  jwksUri?: string | undefined
  issuer?: ExpectedIssuer | undefined
  audience?: string | undefined
  /** off decodes without checking the signature, for a provider with no JWKS; on, a token without `jwksUri`, an issuer or an audience is refused (FR-L2). */
  strict?: boolean | undefined
  /** The algorithms the provider signs ID tokens with, from discovery's `id_token_signing_alg_values_supported`; `none` is never one. */
  algorithms?: string[] | undefined
  allowInsecure?: boolean | undefined
}

// OIDC Core §2: a token missing any of these is not an ID token, whatever its signature.
const REQUIRED_CLAIMS = ['iss', 'sub', 'aud', 'exp', 'iat']

const isTemplate = (issuer?: ExpectedIssuer) => typeof issuer === 'string' && issuer.includes(TENANT_TEMPLATE)

const literalIssuer = (issuer?: ExpectedIssuer) =>
  (Array.isArray(issuer) && issuer) || (typeof issuer === 'string' && !isTemplate(issuer) && issuer) || undefined

const resolveIssuer = (issuer: ExpectedIssuer, claims: IdTokenClaims) => {
  if (typeof issuer === 'function') return issuer(claims)
  return (isTemplate(issuer) && claims.tid && (issuer as string).replace(TENANT_TEMPLATE, String(claims.tid))) || undefined
}

/** Decodes without verifying: decide nothing on the claims unless `createIdTokenVerifier` has passed the token. */
export const parseIdToken = (idToken?: string): IdTokenClaims => {
  try {
    return idToken ? decodeJwt<IdTokenClaims>(idToken) : {}
  } catch {
    return {}
  }
}

// OIDC Core §10.1.1: an unknown `kid` is answered by fetching the keys again, which a browser's HTTP cache would answer with
// the set that lacked it; jose already holds the set in memory. A server runtime keeps no HTTP cache, and workerd refuses the option.
const pastHttpCache = (): RequestInit => ('document' in globalThis ? { cache: 'no-cache' } : {})

/** Holds the remote JWKS for its lifetime: build one per configuration and keep it, or every verification refetches keys. */
export const createIdTokenVerifier = ({
  jwksUri,
  issuer,
  audience,
  strict = true,
  algorithms,
  allowInsecure
}: IdTokenVerifierOptions): IdTokenVerifier => {
  assertSecure(jwksUri, allowInsecure)
  // the platform fetch: left to itself jose reaches for `node:http`, which the core never imports
  const jwksSet =
    jwksUri && strict
      ? createRemoteJWKSet(new URL(jwksUri), { [customFetch]: (url, init) => fetch(url, { ...(init as RequestInit), ...pastHttpCache() }) })
      : undefined
  const literal = literalIssuer(issuer)
  const signedWith = algorithms?.filter(algorithm => algorithm !== 'none')
  return async idToken => {
    if (!idToken) return {}
    if (strict && !jwksSet) return { error: 'No jwks_uri to verify the ID token against' }
    // FR-L2: with nothing to compare `iss` or `aud` against, any provider's token for any client would pass.
    if (strict && !issuer) return { error: 'No issuer to verify the ID token against' }
    if (strict && !audience) return { error: 'No client id to verify the ID token audience against' }
    try {
      if (!jwksSet) return decodeJwt<IdTokenClaims>(idToken)
      const { payload } = await jwtVerify(idToken, jwksSet, {
        ...(literal && { issuer: literal }),
        ...(audience && { audience }),
        ...(signedWith?.length && { algorithms: signedWith }),
        requiredClaims: REQUIRED_CLAIMS
      })
      const issuerMatches = !issuer || !!literal || payload.iss === resolveIssuer(issuer, payload)
      // OIDC Core 3.1.3.7: more than one audience requires azp, and an azp that is present must be us
      const azp = payload.azp as string | undefined
      const azpMatches = !(Array.isArray(payload.aud) && payload.aud.length > 1 && !azp) && !(azp && audience && azp !== audience)
      return issuerMatches && azpMatches ? payload : { error: 'Invalid token' }
    } catch {
      return { error: 'Invalid token' }
    }
  }
}
