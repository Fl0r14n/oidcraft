import { randomString } from '@oidcraft/core'
import { createLocalJWKSet, decodeJwt, jwtVerify } from 'jose'
import type { ResolvedConfig } from '../config'
import { OAuthError } from '../errors'
import { jwksResponseBody } from '../keys/keys'
import type { Client, Session } from '../types'
import { clearCookie } from './cookies'
import { type FrontChannelLogout, frontChannelLogouts, type LogoutNotification, logoutTokens } from './logout'
import { SESSION_COOKIE } from './session'

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
  const client = await clientFromHint(config, hint, params.get('client_id'))

  const requested = params.get('post_logout_redirect_uri')
  const target = resolveTarget(client, requested, Boolean(claims))

  const confirmation = params.get('logout')
  if (confirmation) {
    await acceptConfirmation(config, confirmation, session)
  } else if (session && !claims) {
    // §2: without a verified hint nothing proves the client sent this, and a bare link would sign
    // anyone out who followed it, so the person is asked first.
    return { response: await askToConfirm(config, session, client, params.get('state')), notifications: [], frontChannel: [] }
  }

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

const askToConfirm = async (config: ResolvedConfig, session: Session, client: Client | undefined, state: string | null) => {
  const id = randomString()
  await config.adapter.artifacts.upsert({
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
  const artifact = await config.adapter.artifacts.find('interaction', id)
  if (!artifact?.consumedAt || artifact.payload.interactionKind !== 'logout' || artifact.payload.sessionId !== session?.id) {
    throw new OAuthError('invalid_request', { description: 'this logout confirmation is unknown, expired, or for another session' })
  }
  await config.adapter.artifacts.destroy('interaction', id)
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
