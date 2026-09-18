import { decodeJwt, importJWK, SignJWT } from 'jose'
import type { ResolvedConfig } from './config'
import { signingKey } from './keys'
import type { Artifact, Client } from './types'

export const JWT_ACCESS_TOKEN_TYPE = 'at+jwt'

export type AccessTokenInput = {
  client: Client
  /** The stored artifact's id, which becomes the `jti` and is how revocation still reaches it. */
  id: string
  subject: string | undefined
  scopes: string[]
  expiresAt: Date
  audience?: string | undefined
  confirmation?: Record<string, string> | undefined
  actor?: { client_id: string } | undefined
}

/**
 * RFC 9068. Opt-in per client, because the trade is real: a JWT a resource server can verify
 * offline is a JWT that keeps verifying after it is revoked.
 *
 * The artifact is stored either way, and the `jti` is its id — so revocation and introspection work
 * on a JWT exactly as on an opaque token, for any resource server that asks rather than verifying
 * locally. That is the part that makes the format a choice rather than a one-way door.
 */
export const mintJwtAccessToken = async (config: ResolvedConfig, input: AccessTokenInput) => {
  const keys = await config.adapter.keys.active()
  const alg = keys[0]?.alg
  const key = alg ? signingKey(keys, alg) : undefined
  if (!key || !alg) throw new Error('no signing key is available for a JWT access token')

  return new SignJWT({
    scope: input.scopes.join(' '),
    client_id: input.client.clientId,
    jti: input.id,
    ...(input.confirmation && { cnf: input.confirmation }),
    ...(input.actor && { act: input.actor })
  })
    .setProtectedHeader({ alg, kid: key.kid, typ: JWT_ACCESS_TOKEN_TYPE })
    .setIssuer(config.issuer)
    .setSubject(input.subject ?? input.client.clientId)
    .setAudience(input.audience ?? config.issuer)
    .setIssuedAt()
    .setExpirationTime(Math.floor(input.expiresAt.getTime() / 1000))
    .sign(await importJWK(key.privateJwk as never, alg))
}

const looksLikeJwt = (value: string) => value.split('.').length === 3

/**
 * Finds the artifact behind a presented access token, whichever format it is in.
 *
 * A JWT is only a representation: its `jti` is the stored artifact's id, so a revoked JWT stops
 * working here even though it would still verify offline. Nothing trusts the JWT's own claims —
 * the record is the authority.
 */
export const resolveAccessToken = async (config: ResolvedConfig, presented: string): Promise<Artifact | undefined> => {
  const direct = await config.adapter.artifacts.find('access_token', presented)
  if (direct) return direct
  if (!looksLikeJwt(presented)) return undefined

  try {
    const claims = decodeJwt(presented)
    if (claims.iss !== config.issuer || typeof claims.jti !== 'string') return undefined
    return await config.adapter.artifacts.find('access_token', claims.jti)
  } catch {
    return undefined
  }
}
