import type { Client } from '@oidcraft/adapter'
import { randomString, sha256 } from '@oidcraft/core'
import { base64url, calculateJwkThumbprint, decodeProtectedHeader, importJWK, type JWK, jwtVerify } from 'jose'
import { publicUrl, type ResolvedConfig } from '../config'
import { OAuthError } from '../errors'
import { CLIENT_SIGNING_ALGS } from '../keys/algorithms'
import { readArtifact, writeArtifact } from '../payloads'
import { FAPI_ALGS, FAPI_IAT_SKEW, underFapi } from '../profile/fapi'

const SKEW = 5
const MAX_AGE = 60

export type DpopProof = { jkt: string; jti: string }

// RFC 9449 §8: issued nonces are only read back, never recorded on sight, or a client could name its own.
export const issueNonce = async (config: ResolvedConfig, clientId: string) => {
  const nonce = randomString()
  await writeArtifact(config.adapter.artifacts, {
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

/** §4.3: the query and fragment are ignored, and scheme and host compare as URLs do, case-insensitively. */
const comparableHtu = (uri: unknown) => {
  if (typeof uri !== 'string' || !URL.canParse(uri)) return undefined
  const url = new URL(uri)
  return `${url.origin}${url.pathname}`
}

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
  /** The URI the proof must name. Defaults to the request's URL; behind a proxy, pass the public one (NFR-S6). */
  htu?: string | undefined
  /** Narrower than every asymmetric algorithm, as FAPI 2.0 requires of its clients (FR-C21). */
  algorithms?: string[] | undefined
  /** Seconds an `iat` may run ahead of this clock; FAPI 2.0 requires accepting ten (FR-C21). */
  futureSkew?: number | undefined
}

export const proofOptions = (config: ResolvedConfig, request: Request, clientId: string, client: Client | undefined): VerifyOptions => {
  const fapi = underFapi(config, client)
  return {
    htu: publicUrl(config, request),
    requireNonceFor: config.features.dpopNonces ? clientId : undefined,
    algorithms: fapi ? FAPI_ALGS : undefined,
    futureSkew: fapi ? FAPI_IAT_SKEW : undefined
  }
}

/**
 * Verifies a DPoP proof and returns the key's thumbprint (RFC 9449 §4.3). It proves possession of a key the
 * client chose and nothing else; binding a token to the thumbprint is what makes it useful.
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

  const skew = options.futureSkew ?? SKEW
  const { payload } = await jwtVerify(proof, key, { algorithms: [header.alg], clockTolerance: skew }).catch(() => {
    throw invalid('the DPoP proof signature does not verify')
  })

  if (payload.htm !== request.method) throw invalid(`the DPoP proof is bound to ${String(payload.htm)}, not ${request.method}`)
  const expectedHtu = options.htu ?? htu(request)
  if (comparableHtu(payload.htu) !== comparableHtu(expectedHtu)) {
    throw invalid(`the DPoP proof is bound to ${String(payload.htu)}, not ${expectedHtu}`)
  }

  const iat = payload.iat
  if (typeof iat !== 'number') throw invalid('the DPoP proof has no iat')
  const age = Math.floor(Date.now() / 1000) - iat
  if (age > MAX_AGE || age < -skew) throw invalid('the DPoP proof is too old or not yet valid')

  const jti = payload.jti
  if (typeof jti !== 'string' || !jti) throw invalid('the DPoP proof has no jti')
  // NFR-S5: one proof, one use. Without this a captured proof is replayable for its whole window.
  if (!(await config.adapter.replay.claim('dpop', jti, MAX_AGE + skew))) throw invalid('this DPoP proof has already been used')

  if (options.requireNonceFor) {
    const presented = payload.nonce
    // A nonce stays usable until it expires; the jti check above is what stops replay (RFC 9449 §8).
    const issued = typeof presented === 'string' ? await readArtifact(config.adapter.artifacts, 'dpop_nonce', presented) : undefined
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
