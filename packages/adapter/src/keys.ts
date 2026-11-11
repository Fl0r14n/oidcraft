import { calculateJwkThumbprint, exportJWK, generateKeyPair } from 'jose'
import type { ActiveKey, KeyStore } from './adapter'
import { ConfigurationError } from './errors'

/** Keys from configuration. Production supplies these; nothing is generated behind the operator's back. */
export const staticKeyStore = (keys: ActiveKey[]): KeyStore => {
  if (!keys.length) throw new ConfigurationError(['staticKeyStore was given no keys; the provider cannot sign anything (FR-C10)'])
  for (const key of keys) {
    if (!key.kid) throw new ConfigurationError(['every key needs a kid, or a verifier cannot tell them apart during rotation'])
    if (!key.alg)
      throw new ConfigurationError([`key ${key.kid} declares no alg; the signing key for an algorithm is chosen by it (FR-C10)`])
  }
  if (!keys.some(key => key.alg === 'RS256')) {
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
