import { base64url, importJWK, SignJWT } from 'jose'
import type { ResolvedConfig } from '../config'
import { OAuthError } from '../errors'
import { signingKey } from '../keys/keys'
import { defaultSigningAlg } from '../profile/fapi'
import type { Client, Session } from '../types'

export type IdTokenInput = {
  client: Client
  session: Session
  /** Pairwise or public, decided per client (FR-C18). */
  subject?: string | undefined
  nonce?: string | undefined
  accessToken?: string | undefined
  code?: string | undefined
  claims?: Record<string, unknown> | undefined
}

/** The hash the signing algorithm uses; EdDSA's Ed25519 uses SHA-512 (OIDC Core §3.3.2.11). */
const hashOf = (alg: string) => (alg === 'EdDSA' || alg.endsWith('512') ? 'SHA-512' : alg.endsWith('384') ? 'SHA-384' : 'SHA-256')

/** Left-most half of the hash of the value, base64url — OIDC Core §3.3.2.11. */
const halfHash = async (value: string, alg: string) => {
  const digest = new Uint8Array(await crypto.subtle.digest(hashOf(alg), new TextEncoder().encode(value)))
  return base64url.encode(digest.slice(0, digest.length / 2))
}

export const mintIdToken = async (config: ResolvedConfig, input: IdTokenInput) => {
  const keys = await config.adapter.keys.active()
  const alg = input.client.idTokenSignedResponseAlg ?? defaultSigningAlg(config, input.client, keys)
  const key = alg ? signingKey(keys, alg) : undefined
  if (!key || !alg) {
    throw new OAuthError('server_error', { description: `no ${alg ?? ''} signing key is available; the provider cannot issue an ID token` })
  }

  const now = Math.floor(Date.now() / 1000)
  const payload: Record<string, unknown> = {
    ...input.claims,
    sub: input.subject ?? input.session.accountId,
    auth_time: Math.floor(input.session.authTime.getTime() / 1000),
    ...(input.nonce && { nonce: input.nonce }),
    ...(input.session.acr && { acr: input.session.acr }),
    ...(input.session.amr && { amr: input.session.amr }),
    // FR-F6: when the session was brokered, the provenance is the upstream's, not invented here.
    ...(input.session.idp && { idp: input.session.idp }),
    // Back-Channel Logout 1.0 §2.4: the sid a logout token names, so the client can match the two.
    sid: input.session.id,
    ...(input.accessToken && { at_hash: await halfHash(input.accessToken, alg) }),
    ...(input.code && { c_hash: await halfHash(input.code, alg) })
  }

  return new SignJWT(payload)
    .setProtectedHeader({ alg, kid: key.kid, typ: 'JWT' })
    .setIssuer(config.issuer)
    .setAudience(input.client.clientId)
    .setIssuedAt(now)
    .setExpirationTime(now + config.ttl.idToken)
    .sign(await importJWK(key.privateJwk as never, alg))
}
