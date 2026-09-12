import { calculateJwkThumbprint, decodeProtectedHeader, importJWK, type JWK, jwtVerify } from 'jose'
import type { ResolvedConfig } from './config'
import { OAuthError } from './errors'
import { base64url, sha256 } from './random'

/** RFC 9449 §4.2: asymmetric only. A symmetric alg would let anyone holding the proof mint another. */
const ALLOWED_ALGS = ['ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512', 'RS256', 'RS384', 'RS512', 'EdDSA']

const SKEW = 5
const MAX_AGE = 60

export type DpopProof = { jkt: string; jti: string }

const invalid = (description: string, spec = 'RFC 9449 §4.3') =>
  new OAuthError('invalid_dpop_proof', { description, spec, headers: { 'www-authenticate': 'DPoP error="invalid_dpop_proof"' } })

/** The URI the proof must be bound to: scheme, host and path — never the query or fragment (§4.3). */
export const htu = (request: Request) => {
  const url = new URL(request.url)
  return `${url.origin}${url.pathname}`
}

export const accessTokenHash = async (accessToken: string) => base64url(await sha256(accessToken))

export type VerifyOptions = {
  /** Required when proving possession at a resource: binds the proof to one access token (§4.3). */
  accessToken?: string | undefined
  /** The thumbprint the token was issued against; a mismatch means a different key is presenting it. */
  expectedJkt?: string | undefined
}

/**
 * Verifies a DPoP proof and returns the key's thumbprint (RFC 9449 §4.3).
 *
 * The proof is self-signed by a key the client chose, so it proves possession of that key and
 * nothing else. What makes it useful is binding: the access token records the thumbprint, and a
 * stolen token is worthless without the private key that matches it.
 */
export const verifyDpopProof = async (config: ResolvedConfig, request: Request, options: VerifyOptions = {}): Promise<DpopProof> => {
  const proof = request.headers.get('dpop')
  if (!proof) throw invalid('no DPoP proof was presented')
  if (request.headers.get('dpop')?.includes(',')) throw invalid('more than one DPoP proof was presented')

  let header: ReturnType<typeof decodeProtectedHeader>
  try {
    header = decodeProtectedHeader(proof)
  } catch {
    throw invalid('the DPoP proof is not a JWT')
  }

  if (header.typ !== 'dpop+jwt') throw invalid(`the DPoP proof must have typ "dpop+jwt", got ${String(header.typ)}`)
  if (!header.alg || !ALLOWED_ALGS.includes(header.alg)) throw invalid(`${String(header.alg)} is not an acceptable DPoP algorithm`)
  const jwk = header.jwk as JWK | undefined
  if (!jwk) throw invalid('the DPoP proof carries no jwk')
  // A private member in the header means the client leaked its own key; refuse rather than use it.
  if ('d' in jwk || 'k' in jwk || 'p' in jwk) throw invalid('the DPoP proof jwk carries private key material')

  const key = await importJWK(jwk, header.alg).catch(() => {
    throw invalid('the DPoP proof jwk is unusable')
  })

  const { payload } = await jwtVerify(proof, key, { algorithms: [header.alg], clockTolerance: SKEW }).catch(() => {
    throw invalid('the DPoP proof signature does not verify')
  })

  if (payload.htm !== request.method) throw invalid(`the DPoP proof is bound to ${String(payload.htm)}, not ${request.method}`)
  if (payload.htu !== htu(request)) throw invalid(`the DPoP proof is bound to ${String(payload.htu)}, not ${htu(request)}`)

  const iat = payload.iat
  if (typeof iat !== 'number') throw invalid('the DPoP proof has no iat')
  const age = Math.floor(Date.now() / 1000) - iat
  if (age > MAX_AGE || age < -SKEW) throw invalid('the DPoP proof is too old or not yet valid')

  const jti = payload.jti
  if (typeof jti !== 'string' || !jti) throw invalid('the DPoP proof has no jti')
  // NFR-S5: one proof, one use. Without this a captured proof is replayable for its whole window.
  if (!(await config.adapter.replay.claim('dpop', jti, MAX_AGE + SKEW))) throw invalid('this DPoP proof has already been used')

  if (options.accessToken) {
    const expected = await accessTokenHash(options.accessToken)
    if (payload.ath !== expected) throw invalid('the DPoP proof is not bound to this access token')
  }

  const jkt = await calculateJwkThumbprint(jwk)
  if (options.expectedJkt && jkt !== options.expectedJkt) {
    throw invalid('this access token is bound to a different key', 'RFC 9449 §7.1')
  }

  return { jkt, jti }
}
