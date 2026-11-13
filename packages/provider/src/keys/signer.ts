import type { ActiveKey, Client } from '@oidcraft/adapter'
import { importJWK, type JWTPayload, SignJWT } from 'jose'
import type { ResolvedConfig } from '../config'
import { defaultSigningAlg } from '../profile/fapi'
import { signingKey } from './keys'

/**
 * Signs as this provider for one client: with the algorithm it registered for this kind of token,
 * else the first the profile allows (FR-T1, FR-C21). Undefined when no active key has that algorithm.
 */
export const signerFor = async (config: ResolvedConfig, client: Client | undefined, registered?: string | undefined) => {
  const keys = await config.adapter.keys.active()
  const alg = registered ?? defaultSigningAlg(config, client, keys)
  const key = alg ? signingKey(keys, alg) : undefined
  if (!key || !alg) return undefined
  const privateKey = await importJWK(key.privateJwk as never, alg)
  return {
    alg,
    sign: (payload: JWTPayload, typ?: string) =>
      new SignJWT({ ...payload, iss: config.issuer }).setProtectedHeader({ alg, kid: key.kid, ...(typ && { typ }) }).sign(privateKey)
  }
}

/** One key read per request: a token response signs an ID token and a JWT access token from the same set. */
export const withKeysOnce = (config: ResolvedConfig): ResolvedConfig => {
  let active: Promise<ActiveKey[]> | undefined
  const keys = { active: () => (active ??= config.adapter.keys.active()) }
  return { ...config, adapter: { ...config.adapter, keys } }
}
