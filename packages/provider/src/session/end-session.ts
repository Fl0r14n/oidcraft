import type { Client, Session } from '@oidcraft/adapter'
import { randomString } from '@oidcraft/core'
import { createLocalJWKSet, type JWTPayload, jwtVerify } from 'jose'
import type { ResolvedConfig } from '../config'
import { OAuthError } from '../errors'
import { readForm } from '../form'
import { reportError } from '../hooks'
import { jwksResponseBody } from '../keys/keys'
import { readArtifact, writeArtifact } from '../payloads'
import { bindBrowser } from './browser'
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

// Unverified, a hint would let anyone name a client and be redirected to its URI (OIDC RP-Initiated Logout 1.0 §2).
const verifyHint = async (config: ResolvedConfig, hint: string) => {
  const jwks = createLocalJWKSet(jwksResponseBody(await config.adapter.keys.active()) as never)
  try {
    // §2: a hint has usually expired and need only prove this provider issued it, so its lifetime is not checked.
    // `typ` JWT is what this provider stamps on ID tokens alone; a logout token or a JWT access token is no hint.
    const { payload } = await jwtVerify(hint, jwks, { issuer: config.issuer, typ: 'JWT', clockTolerance: Number.MAX_SAFE_INTEGER })
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
  const params = request.method === 'POST' ? await readForm(request) : url.searchParams

  const hint = params.get('id_token_hint')
  const claims = hint ? await verifyHint(config, hint) : undefined
  const client = await clientFor(config, claims, params.get('client_id'))

  const requested = params.get('post_logout_redirect_uri')
  let target = resolveTarget(client, requested, Boolean(claims))

  const confirmation = params.get('logout')
  if (confirmation) {
    // The confirmed leg carries neither hint nor redirect; where to go was settled, and checked, when the person was asked.
    target = (await acceptConfirmation(config, confirmation, session)).target
  } else if (session && !aboutThisSession(claims, session)) {
    // §2: without a verified hint about this session nothing proves the client sent this, so the person is asked.
    const asked = await askToConfirm(config, request, session, client, params.get('state'), target)
    return { response: asked, notifications: [], frontChannel: [] }
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
  const upstream = session?.idp ? await signOutUpstream(config, request, session, then) : undefined
  const location = upstream ?? then

  if (!location) {
    headers.set('content-type', 'text/plain; charset=utf-8')
    return { response: new Response('You are signed out.', { status: 200, headers }), notifications, frontChannel }
  }
  headers.set('location', location)
  return { response: new Response(null, { status: 303, headers }), notifications, frontChannel }
}

// FR-C11: the session is already gone, so a failing host hook must not cost the notifications that end it at its clients.
const signOutUpstream = async (config: ResolvedConfig, request: Request, session: Session, then: string | undefined) => {
  try {
    return await config.upstreamLogout?.(session, then)
  } catch (error) {
    await reportError(config, request, error)
    return undefined
  }
}

const askToConfirm = async (
  config: ResolvedConfig,
  request: Request,
  session: Session,
  client: Client | undefined,
  state: string | null,
  target: string | undefined
) => {
  const id = randomString()
  const { browser, setCookie } = await bindBrowser(config, request.headers.get('cookie'))
  await writeArtifact(config.adapter.artifacts, {
    id,
    kind: 'interaction',
    clientId: client?.clientId ?? '',
    accountId: session.accountId,
    payload: { interactionKind: 'logout', browser, sessionId: session.id, ...(state !== null && { state }), ...(target && { target }) },
    expiresAt: new Date(Date.now() + config.ttl.interaction * 1000)
  })
  const headers = new Headers({ location: `${config.interactionUrl}/${id}`, 'cache-control': 'no-store' })
  if (setCookie) headers.set('set-cookie', setCookie)
  return new Response(null, { status: 303, headers })
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
  return payload
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
