import { importJWK, SignJWT } from 'jose'
import type { ResolvedConfig } from './config'
import { OAuthError } from './errors'
import { signingKey } from './keys'
import { base64url, sha256 } from './random'
import type { Client, Session } from './types'

export type IdTokenInput = {
  client: Client
  session: Session
  nonce?: string | undefined
  accessToken?: string | undefined
  code?: string | undefined
  claims?: Record<string, unknown> | undefined
}

/** Left-most half of the hash of the value, base64url — OIDC Core §3.3.2.11. */
const halfHash = async (value: string) => {
  const digest = await sha256(value)
  return base64url(digest.slice(0, digest.length / 2))
}

export const mintIdToken = async (config: ResolvedConfig, input: IdTokenInput) => {
  const keys = await config.adapter.keys.active()
  const alg = keys[0]?.alg
  const key = alg ? signingKey(keys, alg) : undefined
  if (!key || !alg) {
    throw new OAuthError('server_error', { description: 'no signing key is available; the provider cannot issue an ID token' })
  }

  const now = Math.floor(Date.now() / 1000)
  const payload: Record<string, unknown> = {
    ...input.claims,
    sub: input.session.accountId,
    auth_time: Math.floor(input.session.authTime.getTime() / 1000),
    ...(input.nonce && { nonce: input.nonce }),
    ...(input.session.acr && { acr: input.session.acr }),
    ...(input.session.amr && { amr: input.session.amr }),
    // FR-F6: when the session was brokered, the provenance is the upstream's, not invented here.
    ...(input.session.idp && { idp: input.session.idp }),
    ...(input.accessToken && { at_hash: await halfHash(input.accessToken) }),
    ...(input.code && { c_hash: await halfHash(input.code) })
  }

  return new SignJWT(payload)
    .setProtectedHeader({ alg, kid: key.kid, typ: 'JWT' })
    .setIssuer(config.issuer)
    .setAudience(input.client.clientId)
    .setIssuedAt(now)
    .setExpirationTime(now + config.ttl.idToken)
    .sign(await importJWK(key.privateJwk as never, alg))
}
