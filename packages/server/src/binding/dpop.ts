import { randomString, sha256 } from '@oidcraft/core'
import { base64url, calculateJwkThumbprint, decodeProtectedHeader, importJWK, type JWK, jwtVerify } from 'jose'
import type { ResolvedConfig } from '../config'
import { OAuthError } from '../errors'
import { CLIENT_SIGNING_ALGS } from '../keys/algorithms'

/** RFC 9449 §4.2: asymmetric only. A symmetric alg would let anyone holding the proof mint another. */

const SKEW = 5
const MAX_AGE = 60

export type DpopProof = { jkt: string; jti: string }

/**
 * A server-chosen nonce the proof must echo (RFC 9449 §8).
 *
 * Without one a proof's freshness rests entirely on `iat`, so a clock-skew allowance is also a
 * window in which a captured proof is replayable at a server that has not seen its `jti`. The nonce
 * removes that: the server names the value, so it knows the proof was minted after it asked.
 *
 * Issued nonces are only ever read back, never recorded on sight: a check that stored the value it
 * was refusing would let a client name its own nonce and have it accepted on the next proof.
 */
export const issueNonce = async (config: ResolvedConfig, clientId: string) => {
  const nonce = randomString()
  await config.adapter.artifacts.upsert({
    id: nonce,
    kind: 'dpop_nonce',
    clientId,
    payload: {},
    expiresAt: new Date(Date.now() + config.ttl.dpopNonce * 1000)
  })
  return nonce
}

const requireNonce = async (config: ResolvedConfig, clientId: string, presented: unknown) => {
  const nonce = await issueNonce(config, clientId)
  const description = presented === undefined ? 'a DPoP nonce is required' : 'that DPoP nonce is not one we issued, or it has expired'
  throw new OAuthError('use_dpop_nonce', {
    description,
    spec: 'RFC 9449 §8',
    status: 400,
    headers: { 'dpop-nonce': nonce }
  })
}

const invalid = (description: string, spec = 'RFC 9449 §4.3') =>
  new OAuthError('invalid_dpop_proof', { description, spec, headers: { 'www-authenticate': 'DPoP error="invalid_dpop_proof"' } })

/** The URI the proof must be bound to: scheme, host and path — never the query or fragment (§4.3). */
export const htu = (request: Request) => {
  const url = new URL(request.url)
  return `${url.origin}${url.pathname}`
}

export const accessTokenHash = async (accessToken: string) => base64url.encode(await sha256(accessToken))

export type VerifyOptions = {
  /** Demand a nonce this provider issued to this client (RFC 9449 §8). */
  requireNonceFor?: string | undefined
  /** Required when proving possession at a resource: binds the proof to one access token (§4.3). */
  accessToken?: string | undefined
  /** The thumbprint the token was issued against; a mismatch means a different key is presenting it. */
  expectedJkt?: string | undefined
  /**
   * The URI the proof must name. Defaults to the request's own URL, which is right only where that is
   * the URL the client used; behind a proxy, pass the public one (NFR-S6).
   */
  htu?: string | undefined
  /** Narrower than every asymmetric algorithm, as FAPI 2.0 requires of its clients (FR-C21). */
  algorithms?: string[] | undefined
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
  if (!header.alg || !(options.algorithms ?? CLIENT_SIGNING_ALGS).includes(header.alg))
    throw invalid(`${String(header.alg)} is not an acceptable DPoP algorithm`)
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
  const expectedHtu = options.htu ?? htu(request)
  if (payload.htu !== expectedHtu) throw invalid(`the DPoP proof is bound to ${String(payload.htu)}, not ${expectedHtu}`)

  const iat = payload.iat
  if (typeof iat !== 'number') throw invalid('the DPoP proof has no iat')
  const age = Math.floor(Date.now() / 1000) - iat
  if (age > MAX_AGE || age < -SKEW) throw invalid('the DPoP proof is too old or not yet valid')

  const jti = payload.jti
  if (typeof jti !== 'string' || !jti) throw invalid('the DPoP proof has no jti')
  // NFR-S5: one proof, one use. Without this a captured proof is replayable for its whole window.
  if (!(await config.adapter.replay.claim('dpop', jti, MAX_AGE + SKEW))) throw invalid('this DPoP proof has already been used')

  if (options.requireNonceFor) {
    const presented = payload.nonce
    // A nonce stays usable until it expires: it marks freshness, and it is the jti check above that
    // stops a proof being replayed (RFC 9449 §8).
    const issued = typeof presented === 'string' ? await config.adapter.artifacts.find('dpop_nonce', presented) : undefined
    if (issued?.clientId !== options.requireNonceFor) await requireNonce(config, options.requireNonceFor, presented)
  }

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
