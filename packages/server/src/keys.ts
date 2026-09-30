import { calculateJwkThumbprint, exportJWK, generateKeyPair, type JWK } from 'jose'
import type { KeyStore } from './adapter'
import { ConfigurationError } from './errors'

export type ActiveKey = { kid: string; alg: string; privateJwk: unknown; publicJwk: unknown }

/** Only the members a verifier needs. Anything else would leak the private key through /jwks. */
const PUBLIC_MEMBERS = ['kty', 'crv', 'x', 'y', 'e', 'n', 'kid', 'alg', 'use'] as const

export const publicJwk = (jwk: JWK) => {
  const out: Record<string, unknown> = {}
  for (const member of PUBLIC_MEMBERS) {
    if (jwk[member] !== undefined) out[member] = jwk[member]
  }
  return out
}

/**
 * The signing key for an algorithm is the first active key that declares it; the rest only verify,
 * so rotating by prepending a key never invalidates a token already in flight (FR-C10, NFR-S7).
 */
export const signingKey = (keys: ActiveKey[], alg: string) => keys.find(key => key.alg === alg)

export const signingAlgorithms = (keys: ActiveKey[]) => [...new Set(keys.map(key => key.alg))]

export const jwksResponseBody = (keys: ActiveKey[]) => ({ keys: keys.map(key => publicJwk(key.publicJwk as JWK)) })

/** Keys from configuration. Production supplies these; nothing is generated behind the operator's back. */
export const staticKeyStore = (keys: ActiveKey[]): KeyStore => {
  if (!keys.length) throw new ConfigurationError(['staticKeyStore was given no keys; the provider cannot sign anything (FR-C10)'])
  for (const key of keys) {
    if (!key.kid) throw new ConfigurationError(['every key needs a kid, or a verifier cannot tell them apart during rotation'])
    if (!key.alg)
      throw new ConfigurationError([`key ${key.kid} declares no alg; the signing key for an algorithm is chosen by it (FR-C10)`])
  }
  if (!signingKey(keys, 'RS256')) {
    throw new ConfigurationError(['the key set has no RS256 key; every OpenID Provider must sign with RS256 (FR-T1, OIDC Core §15.1)'])
  }
  return { active: async () => keys }
}

/**
 * A key pair generated in memory, for development and tests. Every restart produces a new one, which
 * signs everyone out — which is why this is never the production path.
 */
export const generateKey = async (alg = 'ES256'): Promise<ActiveKey> => {
  const { privateKey, publicKey } = await generateKeyPair(alg, { extractable: true })
  const priv = await exportJWK(privateKey)
  const pub = await exportJWK(publicKey)
  const kid = await calculateJwkThumbprint(pub)
  return { kid, alg, privateJwk: { ...priv, kid, alg }, publicJwk: { ...pub, kid, alg, use: 'sig' } }
}

// One RSA key per process: generating one costs ~50ms, and development and tests build a store per provider.
let generatedRsa: Promise<ActiveKey> | undefined

/** `alg` signs by default; an RS256 key is added beside it, because the provider must always offer one (FR-T1). */
export const generatedKeyStore = async (alg = 'ES256') => {
  generatedRsa ??= generateKey('RS256')
  return staticKeyStore(alg === 'RS256' ? [await generatedRsa] : [await generateKey(alg), await generatedRsa])
}
