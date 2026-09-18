import { createRemoteJWKSet, customFetch, jwtVerify } from 'jose'
import { assertSecure, TENANT_TEMPLATE } from './secure'

export type IdTokenClaims = Record<string, any>

export type IdTokenVerifier = (idToken?: string) => Promise<IdTokenClaims>

/** A literal issuer, a set of them, or — when only the token says which — one derived from its claims. */
export type ExpectedIssuer = string | string[] | ((claims: IdTokenClaims) => string | undefined)

export type IdTokenVerifierOptions = {
  jwksUri?: string | undefined
  issuer?: ExpectedIssuer | undefined
  audience?: string | undefined
  /** off decodes without checking the signature — only for a provider that publishes no JWKS */
  strict?: boolean | undefined
  allowInsecure?: boolean | undefined
}

const isTemplate = (issuer?: ExpectedIssuer) => typeof issuer === 'string' && issuer.includes(TENANT_TEMPLATE)

/** What jose can compare itself — a literal or a set. The rest is resolved per token, below. */
const literalIssuer = (issuer?: ExpectedIssuer) =>
  (Array.isArray(issuer) && issuer) || (typeof issuer === 'string' && !isTemplate(issuer) && issuer) || undefined

const resolveIssuer = (issuer: ExpectedIssuer, claims: IdTokenClaims) => {
  if (typeof issuer === 'function') return issuer(claims)
  return (isTemplate(issuer) && claims.tid && (issuer as string).replace(TENANT_TEMPLATE, String(claims.tid))) || undefined
}

/** Decodes without verifying anything. The claims are the provider's word, unchecked — read them only
 * after `createIdTokenVerifier` has passed the token, or for a value nothing is decided on. */
export const parseIdToken = (idToken?: string): IdTokenClaims => {
  const payload = idToken?.split('.')[1]
  if (!payload) return {}
  // JWT segments are base64url (RFC 7515) — atob only accepts base64: map -_ back and re-pad
  const base64 = payload
    .replace(/-/g, '+')
    .replace(/_/g, '/')
    .padEnd(Math.ceil(payload.length / 4) * 4, '=')
  return JSON.parse(
    decodeURIComponent(
      Array.from(atob(base64))
        .map(c => `%${(`00${c.charCodeAt(0).toString(16)}`).slice(-2)}`)
        .join('')
    )
  )
}

/** Holds the remote JWKS for its lifetime, so build one per configuration and keep it — jose caches keys
 * on the set, and a fresh one per verification refetches them. Verifying a second token (to read its
 * claims, say) costs a signature check and no network. */
export const createIdTokenVerifier = ({
  jwksUri,
  issuer,
  audience,
  strict = true,
  allowInsecure
}: IdTokenVerifierOptions): IdTokenVerifier => {
  // Keys fetched over http are keys an attacker on the path chooses, which makes every signature
  // check below decorative.
  assertSecure(jwksUri, allowInsecure)
  // jose is handed the platform fetch: left to itself it reaches for `node:http`, which drags a Node
  // shim into Bun, Deno, workers and the browser for what is one GET of a JSON document.
  const jwksSet =
    jwksUri && strict ? createRemoteJWKSet(new URL(jwksUri), { [customFetch]: (url, init) => fetch(url, init as RequestInit) }) : undefined
  const literal = literalIssuer(issuer)
  return async idToken => {
    if (!idToken) return {}
    if (!jwksSet) return parseIdToken(idToken)
    try {
      const { payload } = await jwtVerify(idToken, jwksSet, {
        ...(literal && { issuer: literal }),
        ...(audience && { audience })
      })
      if (issuer && !literal && payload.iss !== resolveIssuer(issuer, payload)) {
        return { error: 'Invalid token' }
      }
      // OIDC Core 3.1.3.7: more than one audience requires azp, and an azp that is present must be us
      const azp = payload.azp as string | undefined
      if ((Array.isArray(payload.aud) && payload.aud.length > 1 && !azp) || (azp && audience && azp !== audience)) {
        return { error: 'Invalid token' }
      }
      return payload
    } catch {
      return { error: 'Invalid token' }
    }
  }
}
