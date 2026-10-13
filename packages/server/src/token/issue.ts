import { randomString } from '@oidcraft/core'
import type { ResolvedConfig } from '../config'
import { OAuthError } from '../errors'
import type { Artifact, Client, Grant, Session } from '../types'
import { mintJwtAccessToken } from './access-token'
import { mintIdToken } from './id-token'
import { subjectFor } from './subjects'

/** What a token is sender-constrained to: a DPoP key (RFC 9449), a client certificate (RFC 8705), or both. */
export type Binding = { jkt?: string | undefined; x5t?: string | undefined }

export const confirmationOf = ({ jkt, x5t }: Binding) => (jkt || x5t ? { ...(jkt && { jkt }), ...(x5t && { 'x5t#S256': x5t }) } : undefined)

export const issueTokens = async (
  config: ResolvedConfig,
  client: Client,
  grant: Grant,
  session: Session,
  scopes: string[],
  {
    nonce,
    binding = {},
    authorizationDetails,
    refreshScopes = scopes
  }: {
    nonce?: string | undefined
    binding?: Binding
    authorizationDetails?: unknown[] | undefined
    /** RFC 6749 §6: a rotated refresh token keeps its own scope even when the access token is narrowed. */
    refreshScopes?: string[]
  } = {}
) => {
  const { jkt } = binding
  const cnf = confirmationOf(binding)
  // FR-C11: logout notifies the session's clients, so every client it signs in to must be on the list.
  if (!session.clients.includes(client.clientId)) {
    const current = (await config.adapter.sessions.find(session.id)) ?? session
    await config.adapter.sessions.upsert({ ...current, clients: [...new Set([...current.clients, client.clientId])] })
  }

  const accessTokenId = randomString()
  const expiresIn = config.ttl.accessToken
  const accessTokenExpiry = new Date(Date.now() + expiresIn * 1000)
  // FR-C18: what this client is told the user is called, which may not be the local account id.
  const subject = await subjectFor(config, client, session.accountId)

  await config.adapter.artifacts.upsert({
    id: accessTokenId,
    kind: 'access_token',
    clientId: client.clientId,
    accountId: session.accountId,
    grantId: grant.id,
    // RFC 9449 §6: the confirmation claim is what makes the token useless without the key.
    payload: {
      iat: Math.floor(Date.now() / 1000),
      scopes,
      sessionId: session.id,
      subject,
      ...(authorizationDetails && { authorizationDetails }),
      ...(cnf && { cnf })
    },
    expiresAt: accessTokenExpiry
  })

  const accessToken =
    client.accessTokenFormat === 'jwt'
      ? await mintJwtAccessToken(config, {
          client,
          id: accessTokenId,
          subject,
          scopes,
          expiresAt: accessTokenExpiry,
          ...(cnf && { confirmation: cnf })
        })
      : accessTokenId

  const refreshX5t = client.tokenEndpointAuthMethod === 'none' ? binding.x5t : undefined
  let refreshToken: string | undefined
  // Only when the client asked for it: a refresh token nobody requested is a credential nobody guards.
  if (refreshScopes.includes('offline_access') && client.grantTypes.includes('refresh_token')) {
    refreshToken = randomString()
    await config.adapter.artifacts.upsert({
      id: refreshToken,
      kind: 'refresh_token',
      clientId: client.clientId,
      accountId: session.accountId,
      grantId: grant.id,
      // The binding must survive rotation, or it evaporates on the first refresh (RFC 9449 §5). A
      // certificate binds a refresh token only for a public client; a confidential one is held to
      // its certificate by authenticating with it (RFC 8705 §4).
      payload: {
        iat: Math.floor(Date.now() / 1000),
        scopes: refreshScopes,
        sessionId: session.id,
        ...((jkt || refreshX5t) && { cnf: confirmationOf({ jkt, x5t: refreshX5t }) })
      },
      expiresAt: new Date(Date.now() + config.ttl.refreshToken * 1000)
    })
  }

  // OIDC Core §3.1.2.1: without openid this is plain OAuth, and an ID token would answer a question nobody asked.
  const idToken = scopes.includes('openid')
    ? await mintIdToken(config, {
        client,
        session,
        subject,
        nonce,
        // OIDC Core §5.4: an access token is always issued here, so scope claims are UserInfo's to release.
        accessToken
      })
    : undefined

  return {
    access_token: accessToken,
    token_type: jkt ? 'DPoP' : 'Bearer',
    expires_in: expiresIn,
    scope: scopes.join(' '),
    ...(authorizationDetails && { authorization_details: authorizationDetails }),
    ...(idToken && { id_token: idToken }),
    ...(refreshToken && { refresh_token: refreshToken })
  }
}

export const loadGrantAndSession = async (config: ResolvedConfig, artifact: Artifact) => {
  const grant = artifact.grantId ? await config.adapter.grants.find(artifact.grantId) : undefined
  if (!grant) throw new OAuthError('invalid_grant', { description: 'the grant behind this token no longer exists' })

  const session = await config.adapter.sessions.find(artifact.payload.sessionId as string)
  if (!session) throw new OAuthError('invalid_grant', { description: 'the session behind this token has ended' })

  return { grant, session }
}
