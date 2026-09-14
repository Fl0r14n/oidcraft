import { createLocalJWKSet, decodeJwt, importJWK, jwtVerify, SignJWT } from 'jose'
import type { ResolvedConfig } from '../config'
import { clearCookie } from '../cookies'
import { OAuthError } from '../errors'
import { jwksResponseBody, signingKey } from '../keys'
import { token } from '../random'
import { SESSION_COOKIE } from '../session'
import type { Client, Session } from '../types'

export type LogoutNotification = { clientId: string; uri: string; logoutToken: string }

/** A URL the host loads in an iframe (OIDC Front-Channel Logout 1.0 §2). */
export type FrontChannelLogout = { clientId: string; uri: string }

/**
 * The front-channel half (FR-C11). The core produces the URLs and does not render the iframes: it
 * emits no HTML (ARCHITECTURE.md §3.2), and the page they live in is the host's to style and to
 * decide the timeout of.
 *
 * `iss` and `sid` go on the URL only for a client that asked for them — §2 makes it opt-in, and
 * sending a session identifier to a client that never requested one leaks it for no purpose.
 */
export const frontChannelLogouts = async (config: ResolvedConfig, session: Session): Promise<FrontChannelLogout[]> => {
  const out: FrontChannelLogout[] = []
  for (const clientId of session.clients) {
    const client = await config.adapter.clients.find(clientId)
    if (!client?.frontchannelLogoutUri) continue
    const uri = new URL(client.frontchannelLogoutUri)
    if (client.frontchannelLogoutSessionRequired) {
      uri.searchParams.set('iss', config.issuer)
      uri.searchParams.set('sid', session.id)
    }
    out.push({ clientId, uri: uri.toString() })
  }
  return out
}

/**
 * Back-channel logout tokens for the host to deliver (OIDC Back-Channel Logout 1.0 §2.4).
 *
 * The core mints them and does not POST them: it performs no I/O (FR-A1), and delivery is a
 * fan-out with retries and timeouts that belongs to the host's job runner, not to a request.
 */
export const logoutTokens = async (config: ResolvedConfig, session: Session): Promise<LogoutNotification[]> => {
  const keys = await config.adapter.keys.active()
  const alg = keys[0]?.alg
  const key = alg ? signingKey(keys, alg) : undefined
  if (!key || !alg) return []

  const notifications: LogoutNotification[] = []
  for (const clientId of session.clients) {
    const client = await config.adapter.clients.find(clientId)
    if (!client?.backchannelLogoutUri) continue

    const logoutToken = await new SignJWT({
      sub: session.accountId,
      sid: session.id,
      // The marker that makes this a logout token and not a re-usable ID token (§2.4).
      events: { 'http://schemas.openid.net/event/backchannel-logout': {} },
      jti: token(16)
    })
      .setProtectedHeader({ alg, kid: key.kid, typ: 'logout+jwt' })
      .setIssuer(config.issuer)
      .setAudience(clientId)
      .setIssuedAt()
      .setExpirationTime('2m')
      .sign(await importJWK(key.privateJwk as never, alg))

    notifications.push({ clientId, uri: client.backchannelLogoutUri, logoutToken })
  }
  return notifications
}

const clientFromHint = async (config: ResolvedConfig, hint: string | null, clientId: string | null) => {
  if (clientId) return config.adapter.clients.find(clientId)
  if (!hint) return undefined
  try {
    return await config.adapter.clients.find(decodeJwt(hint).aud as string)
  } catch {
    return undefined
  }
}

/**
 * An `id_token_hint` is only a hint until it is verified. An unverified one would let anyone name a
 * client and be redirected to that client's registered URI (OIDC RP-Initiated Logout 1.0 §2).
 */
const verifyHint = async (config: ResolvedConfig, hint: string) => {
  const jwks = createLocalJWKSet(jwksResponseBody(await config.adapter.keys.active()) as never)
  try {
    const { payload } = await jwtVerify(hint, jwks, { issuer: config.issuer })
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
  const client = await clientFromHint(config, hint, params.get('client_id'))

  const requested = params.get('post_logout_redirect_uri')
  const target = resolveTarget(client, requested, Boolean(claims))

  const notifications = session ? await logoutTokens(config, session) : []
  const frontChannel = session ? await frontChannelLogouts(config, session) : []
  if (session) await config.adapter.sessions.destroy(session.id)

  const headers = new Headers({
    'cache-control': 'no-store',
    'set-cookie': clearCookie(SESSION_COOKIE, { secure: config.issuerUrl.protocol === 'https:' })
  })

  if (!target) {
    headers.set('content-type', 'text/plain; charset=utf-8')
    return { response: new Response('You are signed out.', { status: 200, headers }), notifications, frontChannel }
  }

  const state = params.get('state')
  const redirect = new URL(target)
  if (state !== null) redirect.searchParams.set('state', state)
  headers.set('location', redirect.toString())
  return { response: new Response(null, { status: 303, headers }), notifications, frontChannel }
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
      description: `post_logout_redirect_uri ${requested} is not registered for ${client.clientId}`
    })
  }
  return requested
}
