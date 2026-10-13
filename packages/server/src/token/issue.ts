import { randomString } from '@oidcraft/core'
import type { ResolvedConfig } from '../config'
import { OAuthError } from '../errors'
import type { Artifact, Client, Grant, Session } from '../types'
import { type Binding, confirmationOf, issueAccessToken } from './access-token'
import { mintIdToken } from './id-token'
import { subjectFor } from './subjects'

export { type Binding, confirmationOf } from './access-token'

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
    refreshScopes = scopes,
    familyExpiresAt
  }: {
    nonce?: string | undefined
    binding?: Binding
    authorizationDetails?: unknown[] | undefined
    /** RFC 6749 §6: a rotated refresh token keeps its own scope even when the access token is narrowed. */
    refreshScopes?: string[]
    /** Epoch seconds; carried from the token being rotated so the family's lifetime never slides. */
    familyExpiresAt?: number | undefined
  } = {}
) => {
  const { jkt } = binding
  // FR-C11: logout notifies the session's clients, so every client it signs in to must be on the list.
  // An offline refresh may outlive the session; one that has ended is not brought back.
  if (!session.clients.includes(client.clientId)) {
    const current = await config.adapter.sessions.find(session.id)
    if (current) await config.adapter.sessions.upsert({ ...current, clients: [...new Set([...current.clients, client.clientId])] })
  }

  // FR-C18: what this client is told the user is called, which may not be the local account id.
  const subject = await subjectFor(config, client, session.accountId)
  const access = await issueAccessToken(config, {
    client,
    scopes,
    binding,
    accountId: session.accountId,
    grantId: grant.id,
    sessionId: session.id,
    subject,
    authorizationDetails
  })
  const accessToken = access.token

  const refreshX5t = client.tokenEndpointAuthMethod === 'none' ? binding.x5t : undefined
  let refreshToken: string | undefined
  // Only when the client asked for it: a refresh token nobody requested is a credential nobody guards.
  if (refreshScopes.includes('offline_access') && client.grantTypes.includes('refresh_token')) {
    refreshToken = randomString()
    const now = Math.floor(Date.now() / 1000)
    const familyEnd = familyExpiresAt ?? now + config.ttl.refreshTokenFamily
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
        iat: now,
        scopes: refreshScopes,
        sessionId: session.id,
        // offline_access is for when the user is gone: the sign-in it rests on travels with it.
        signIn: snapshotOf(session),
        familyExpiresAt: familyEnd,
        ...((jkt || refreshX5t) && { cnf: confirmationOf({ jkt, x5t: refreshX5t }) })
      },
      expiresAt: new Date(Math.min(now + config.ttl.refreshToken, familyEnd) * 1000)
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
    token_type: access.tokenType,
    expires_in: access.expiresIn,
    scope: scopes.join(' '),
    ...(authorizationDetails && { authorization_details: authorizationDetails }),
    ...(idToken && { id_token: idToken }),
    ...(refreshToken && { refresh_token: refreshToken })
  }
}

type SignIn = { id: string; accountId: string; authTime: number; acr?: string; amr?: string[]; idp?: string }

const snapshotOf = (session: Session): SignIn => ({
  id: session.id,
  accountId: session.accountId,
  authTime: session.authTime.getTime(),
  ...(session.acr && { acr: session.acr }),
  ...(session.amr && { amr: session.amr }),
  ...(session.idp && { idp: session.idp })
})

/**
 * The session behind a refresh token, or the sign-in it recorded once that session has ended:
 * offline access must not die with the browser session (OIDC Core §11). Revoking the grant still ends it.
 */
export const loadGrantAndSignIn = async (config: ResolvedConfig, artifact: Artifact) => {
  const grant = artifact.grantId ? await config.adapter.grants.find(artifact.grantId) : undefined
  if (!grant) throw new OAuthError('invalid_grant', { description: 'the grant behind this token no longer exists' })
  const live = await config.adapter.sessions.find(artifact.payload.sessionId as string)
  if (live) return { grant, session: live }
  const signIn = artifact.payload.signIn as SignIn | undefined
  if (!signIn) throw new OAuthError('invalid_grant', { description: 'the session behind this token has ended' })
  const { authTime, ...rest } = signIn
  const session: Session = { ...rest, authTime: new Date(authTime), clients: [], expiresAt: new Date() }
  return { grant, session }
}

export const loadGrantAndSession = async (config: ResolvedConfig, artifact: Artifact) => {
  const grant = artifact.grantId ? await config.adapter.grants.find(artifact.grantId) : undefined
  if (!grant) throw new OAuthError('invalid_grant', { description: 'the grant behind this token no longer exists' })

  const session = await config.adapter.sessions.find(artifact.payload.sessionId as string)
  if (!session) throw new OAuthError('invalid_grant', { description: 'the session behind this token has ended' })

  return { grant, session }
}
