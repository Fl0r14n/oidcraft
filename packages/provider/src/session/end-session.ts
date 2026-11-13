import type { Client, Session } from '@oidcraft/adapter'
import { randomString } from '@oidcraft/core'
import { createLocalJWKSet, type JWTPayload, jwtVerify } from 'jose'
import type { ResolvedConfig } from '../config'
import { OAuthError } from '../errors'
import { jwksResponseBody } from '../keys/keys'
import { readArtifact, writeArtifact } from '../payloads'
import { clearCookie } from './cookies'
import { type FrontChannelLogout, frontChannelLogouts, type LogoutNotification, logoutTokens } from './logout'
import { sessionCookie } from './session'

const audiencesOf = (claims: JWTPayload | undefined) => (claims?.aud === undefined ? [] : [claims.aud].flat())

/** The client a logout is for: the one the verified hint was issued to, which a `client_id` sent with it must name (FR-C11). */
const clientFor = async (config: ResolvedConfig, claims: JWTPayload | undefined, clientId: string | null) => {
  const audiences = audiencesOf(claims)
  if (claims && clientId && !audiences.includes(clientId)) {
    throw new OAuthError('invalid_request', {
      description: `client_id ${clientId} is not the client the id_token_hint was issued to`,
      spec: 'OIDC RP-Initiated Logout 1.0 §2'
    })
  }
  const id = clientId ?? audiences[0]
  return id ? config.adapter.clients.find(id) : undefined
}

/** A hint is about this browser only when it names the session the browser holds (FR-C11). */
const aboutThisSession = (claims: JWTPayload | undefined, session: Session | undefined) =>
  Boolean(claims && (!session || claims.sid === session.id))

/**
 * An `id_token_hint` is only a hint until it is verified. An unverified one would let anyone name a
 * client and be redirected to that client's registered URI (OIDC RP-Initiated Logout 1.0 §2).
 */
const verifyHint = async (config: ResolvedConfig, hint: string) => {
  const jwks = createLocalJWKSet(jwksResponseBody(await config.adapter.keys.active()) as never)
  try {
    // §2: the hint is usually an ID token that has long expired by the time the user signs out, and
    // it only has to prove this provider issued it, so its lifetime is not checked.
    const { payload } = await jwtVerify(hint, jwks, { issuer: config.issuer, clockTolerance: Number.MAX_SAFE_INTEGER })
    return payload
  } catch {
    throw new OAuthError('invalid_request', {
      description: 'id_token_hint is not a token this provider issued',
      spec: 'OIDC RP-Initiated Logout 1.0 §2'
    })
  }
}

export type EndSessionResult = { response: Response; notifications: LogoutNotification[]; frontChannel: FrontChannelLogout[] }

export const endSessionEndpoint = async (
  config: ResolvedConfig,
  request: Request,
  session: Session | undefined
): Promise<EndSessionResult> => {
  const url = new URL(request.url)
  const params = request.method === 'POST' ? new URLSearchParams(await request.text()) : url.searchParams

  const hint = params.get('id_token_hint')
  const claims = hint ? await verifyHint(config, hint) : undefined
  const client = await clientFor(config, claims, params.get('client_id'))

  const requested = params.get('post_logout_redirect_uri')
  const target = resolveTarget(client, requested, Boolean(claims))

  const confirmation = params.get('logout')
  if (confirmation) {
    await acceptConfirmation(config, confirmation, session)
  } else if (session && !aboutThisSession(claims, session)) {
    // §2: without a verified hint about this session nothing proves the client sent this, and a bare
    // link would sign anyone out who followed it, so the person is asked first.
    return { response: await askToConfirm(config, session, client, params.get('state')), notifications: [], frontChannel: [] }
  }

  const notifications = session ? await logoutTokens(config, session) : []
  const frontChannel = session ? await frontChannelLogouts(config, session) : []
  if (session) await config.adapter.sessions.destroy(session.id)

  const headers = new Headers({
    'cache-control': 'no-store',
    'set-cookie': clearCookie(sessionCookie(config), { secure: config.issuerUrl.protocol === 'https:' })
  })

  const state = params.get('state')
  const then = target === undefined ? undefined : withState(target, state)
  // FR-F8: a brokered session is signed out upstream too, when the host continues it there.
  const upstream = session?.idp && config.upstreamLogout ? await config.upstreamLogout(session, then) : undefined
  const location = upstream ?? then

  if (!location) {
    headers.set('content-type', 'text/plain; charset=utf-8')
    return { response: new Response('You are signed out.', { status: 200, headers }), notifications, frontChannel }
  }
  headers.set('location', location)
  return { response: new Response(null, { status: 303, headers }), notifications, frontChannel }
}

const askToConfirm = async (config: ResolvedConfig, session: Session, client: Client | undefined, state: string | null) => {
  const id = randomString()
  await writeArtifact(config.adapter.artifacts, {
    id,
    kind: 'interaction',
    clientId: client?.clientId ?? '',
    accountId: session.accountId,
    payload: { interactionKind: 'logout', sessionId: session.id, ...(state !== null && { state }) },
    expiresAt: new Date(Date.now() + config.ttl.interaction * 1000)
  })
  return new Response(null, { status: 303, headers: { location: `${config.interactionUrl}/${id}`, 'cache-control': 'no-store' } })
}

/** Only a confirmed logout interaction for this very session ends it, and only once. */
const acceptConfirmation = async (config: ResolvedConfig, id: string, session: Session | undefined) => {
  const artifact = await readArtifact(config.adapter.artifacts, 'interaction', id)
  const payload = artifact?.payload
  if (!artifact?.consumedAt || payload?.interactionKind !== 'logout' || payload.sessionId !== session?.id) {
    throw new OAuthError('invalid_request', {
      description: 'this logout confirmation is unknown, expired, or for another session',
      spec: 'OIDC RP-Initiated Logout 1.0 §2'
    })
  }
  await config.adapter.artifacts.destroy('interaction', id)
}

const withState = (target: string, state: string | null) => {
  const redirect = new URL(target)
  if (state !== null) redirect.searchParams.set('state', state)
  return redirect.toString()
}

const resolveTarget = (client: Client | undefined, requested: string | null, verifiedHint: boolean) => {
  if (!requested) return undefined
  // NFR-S2 again: exact match against what that client registered, and only when we know the client.
  if (!client || !verifiedHint) {
    throw new OAuthError('invalid_request', {
      description: 'post_logout_redirect_uri requires a verified id_token_hint identifying the client',
      spec: 'OIDC RP-Initiated Logout 1.0 §2'
    })
  }
  if (!client.postLogoutRedirectUris?.includes(requested)) {
    throw new OAuthError('invalid_request', {
      description: `post_logout_redirect_uri ${requested} is not registered for ${client.clientId}`,
      spec: 'OIDC RP-Initiated Logout 1.0 §2'
    })
  }
  return requested
}
