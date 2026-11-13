import type { ActiveKey } from '@oidcraft/adapter'
import type { JWK } from 'jose'

/** Only the members a verifier needs. Anything else would leak the private key through /jwks. */
const PUBLIC_MEMBERS = ['kty', 'crv', 'x', 'y', 'e', 'n', 'kid', 'alg', 'use'] as const

export const publicJwk = (jwk: JWK) => {
  const out: Record<string, unknown> = {}
  for (const member of PUBLIC_MEMBERS) {
    if (jwk[member] !== undefined) out[member] = jwk[member]
  }
  return out
}

// The first active key per algorithm signs, so rotating by prepending never invalidates a token in flight (FR-C10, NFR-S7).
export const signingKey = (keys: ActiveKey[], alg: string) => keys.find(key => key.alg === alg)

export const signingAlgorithms = (keys: ActiveKey[]) => [...new Set(keys.map(key => key.alg))]

export const jwksResponseBody = (keys: ActiveKey[]) => ({ keys: keys.map(key => publicJwk(key.publicJwk as JWK)) })
