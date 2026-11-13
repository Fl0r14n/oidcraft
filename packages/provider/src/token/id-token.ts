import type { Client, Session } from '@oidcraft/adapter'
import { base64url } from 'jose'
import type { ResolvedConfig } from '../config'
import { OAuthError } from '../errors'
import { signerFor } from '../keys/signer'

export type IdTokenInput = {
  client: Client
  session: Session
  /** Pairwise or public, decided per client (FR-C18). */
  subject?: string | undefined
  nonce?: string | undefined
  accessToken?: string | undefined
  claims?: Record<string, unknown> | undefined
}

/** The hash the signing algorithm uses; EdDSA's Ed25519 uses SHA-512 (OIDC Core §3.3.2.11). */
const hashOf = (alg: string) => (alg === 'EdDSA' || alg.endsWith('512') ? 'SHA-512' : alg.endsWith('384') ? 'SHA-384' : 'SHA-256')

/** Left-most half of the hash of the value, base64url — OIDC Core §3.3.2.11. */
const halfHash = async (value: string, alg: string) => {
  const digest = new Uint8Array(await crypto.subtle.digest(hashOf(alg), new TextEncoder().encode(value)))
  return base64url.encode(digest.slice(0, digest.length / 2))
}

// What says how and when the person signed in is the session's to state, never an account claim's (FR-F6).
const PROTOCOL_CLAIMS = new Set(['iss', 'sub', 'aud', 'exp', 'iat', 'nbf', 'jti', 'nonce', 'acr', 'amr', 'auth_time', 'azp', 'sid', 'idp'])

const released = (claims: Record<string, unknown> | undefined) =>
  Object.fromEntries(Object.entries(claims ?? {}).filter(([name]) => !PROTOCOL_CLAIMS.has(name) && !name.endsWith('_hash')))

export const mintIdToken = async (config: ResolvedConfig, input: IdTokenInput) => {
  const signer = await signerFor(config, input.client, input.client.idTokenSignedResponseAlg)
  if (!signer) {
    const named = input.client.idTokenSignedResponseAlg ?? ''
    throw new OAuthError('server_error', { description: `no ${named} signing key is available; the provider cannot issue an ID token` })
  }
  const { alg } = signer

  const now = Math.floor(Date.now() / 1000)
  const payload: Record<string, unknown> = {
    ...released(input.claims),
    aud: input.client.clientId,
    iat: now,
    exp: now + config.ttl.idToken,
    sub: input.subject ?? input.session.accountId,
    auth_time: Math.floor(input.session.authTime.getTime() / 1000),
    ...(input.nonce && { nonce: input.nonce }),
    ...(input.session.acr && { acr: input.session.acr }),
    ...(input.session.amr && { amr: input.session.amr }),
    // FR-F6: when the session was brokered, the provenance is the upstream's, not invented here.
    ...(input.session.idp && { idp: input.session.idp }),
    // Back-Channel Logout 1.0 §2.4: the sid a logout token names, so the client can match the two.
    sid: input.session.id,
    ...(input.accessToken && { at_hash: await halfHash(input.accessToken, alg) })
  }

  return signer.sign(payload, 'JWT')
}
