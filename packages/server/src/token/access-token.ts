import { randomString } from '@oidcraft/core'
import { decodeJwt, importJWK, SignJWT } from 'jose'
import type { ResolvedConfig } from '../config'
import { signingKey } from '../keys/keys'
import type { Artifact, ArtifactKind, Client } from '../types'

export const JWT_ACCESS_TOKEN_TYPE = 'at+jwt'

/** What a token is sender-constrained to: a DPoP key (RFC 9449), a client certificate (RFC 8705), or both. */
export type Binding = { jkt?: string | undefined; x5t?: string | undefined }

export const confirmationOf = ({ jkt, x5t }: Binding) => (jkt || x5t ? { ...(jkt && { jkt }), ...(x5t && { 'x5t#S256': x5t }) } : undefined)

export type AccessTokenRequest = {
  client: Client
  scopes: string[]
  binding: Binding
  accountId?: string | undefined
  grantId?: string | undefined
  sessionId?: string | undefined
  /** FR-C18: what this client was told the user is called. */
  subject?: string | undefined
  /** Defaults to the access token lifetime; an exchange caps it at its subject token's. */
  expiresAt?: Date | undefined
  authorizationDetails?: unknown[] | undefined
  /** RFC 8693 §4.1: who is acting, so a resource server can tell delegation from the real thing. */
  actor?: { client_id: string } | undefined
  resource?: string | undefined
  audience?: string | undefined
}

/**
 * The one place an access token is made: stored, then shaped as the client asked (FR-T2). The
 * stored record is the authority either way, which is what keeps a JWT revocable.
 */
export const issueAccessToken = async (config: ResolvedConfig, request: AccessTokenRequest) => {
  const id = randomString()
  const expiresAt = request.expiresAt ?? new Date(Date.now() + config.ttl.accessToken * 1000)
  // RFC 9449 §6: the confirmation claim is what makes the token useless without the key.
  const cnf = confirmationOf(request.binding)
  await config.adapter.artifacts.upsert({
    id,
    kind: 'access_token',
    clientId: request.client.clientId,
    ...(request.accountId && { accountId: request.accountId }),
    ...(request.grantId && { grantId: request.grantId }),
    payload: {
      iat: Math.floor(Date.now() / 1000),
      scopes: request.scopes,
      ...(request.sessionId && { sessionId: request.sessionId }),
      ...(request.subject && { subject: request.subject }),
      ...(request.authorizationDetails && { authorizationDetails: request.authorizationDetails }),
      ...(request.actor && { act: request.actor }),
      ...(request.resource && { resource: request.resource }),
      ...(request.audience && { aud: request.audience }),
      ...(cnf && { cnf })
    },
    expiresAt
  })

  const token =
    request.client.accessTokenFormat === 'jwt'
      ? await mintJwtAccessToken(config, {
          client: request.client,
          id,
          subject: request.subject,
          scopes: request.scopes,
          expiresAt,
          audience: request.audience,
          actor: request.actor,
          ...(cnf && { confirmation: cnf })
        })
      : id

  return {
    token,
    tokenType: request.binding.jkt ? 'DPoP' : 'Bearer',
    expiresIn: Math.max(0, Math.floor((expiresAt.getTime() - Date.now()) / 1000))
  }
}

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

/** An access token by whichever form it was presented in; any other kind by its id. */
export const findPresented = (config: ResolvedConfig, kind: ArtifactKind, presented: string) =>
  kind === 'access_token' ? resolveAccessToken(config, presented) : config.adapter.artifacts.find(kind, presented)

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
