import type { Artifact, ArtifactKind, Client } from '@oidcraft/adapter'
import { randomString } from '@oidcraft/core'
import { createLocalJWKSet, importJWK, type JSONWebKeySet, jwtVerify, SignJWT } from 'jose'
import type { ResolvedConfig } from '../config'
import { jwksResponseBody, signingKey } from '../keys/keys'
import { defaultSigningAlg } from '../profile/fapi'

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
  familyId?: string | undefined
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
  const jwt = request.client.accessTokenFormat === 'jwt'
  const expiresAt = request.expiresAt ?? new Date(Date.now() + config.ttl.accessToken * 1000)
  // RFC 9449 §6: the confirmation claim is what makes the token useless without the key.
  const cnf = confirmationOf(request.binding)
  await config.adapter.artifacts.upsert({
    id,
    kind: 'access_token',
    clientId: request.client.clientId,
    ...(request.accountId && { accountId: request.accountId }),
    ...(request.grantId && { grantId: request.grantId }),
    ...(request.familyId && { familyId: request.familyId }),
    payload: {
      iat: Math.floor(Date.now() / 1000),
      scopes: request.scopes,
      ...(request.sessionId && { sessionId: request.sessionId }),
      ...(request.subject && { subject: request.subject }),
      ...(request.authorizationDetails && { authorizationDetails: request.authorizationDetails }),
      ...(request.actor && { act: request.actor }),
      ...(request.resource && { resource: request.resource }),
      ...(request.audience && { aud: request.audience }),
      ...(cnf && { cnf }),
      ...(jwt && { format: 'jwt' })
    },
    expiresAt
  })

  const token = jwt
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
  /** The `jti`, which the artifact is stored under a hash of, and is how revocation still reaches it. */
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
 * The artifact is stored either way, found by the `jti` — so revocation and introspection work
 * on a JWT exactly as on an opaque token, for any resource server that asks rather than verifying
 * locally. That is the part that makes the format a choice rather than a one-way door.
 */
export const mintJwtAccessToken = async (config: ResolvedConfig, input: AccessTokenInput) => {
  const keys = await config.adapter.keys.active()
  const alg = defaultSigningAlg(config, input.client, keys)
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
 * A JWT is only a representation: the record is the authority, so a revoked JWT stops working here
 * even though it would still verify offline. Its `jti` finds that record only once the signature
 * verifies, and never when presented bare: a `jti` is in every resource server's logs (FR-T2).
 */
export const resolveAccessToken = async (config: ResolvedConfig, presented: string): Promise<Artifact | undefined> => {
  if (!looksLikeJwt(presented)) {
    const opaque = await config.adapter.artifacts.find('access_token', presented)
    return opaque?.payload.format === 'jwt' ? undefined : opaque
  }

  try {
    const keys = createLocalJWKSet(jwksResponseBody(await config.adapter.keys.active()) as JSONWebKeySet)
    const { payload } = await jwtVerify(presented, keys, { issuer: config.issuer, typ: JWT_ACCESS_TOKEN_TYPE })
    return typeof payload.jti === 'string' ? await config.adapter.artifacts.find('access_token', payload.jti) : undefined
  } catch {
    return undefined
  }
}
