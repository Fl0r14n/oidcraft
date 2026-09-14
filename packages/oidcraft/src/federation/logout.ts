import { createLocalJWKSet, decodeJwt, type JSONWebKeySet, jwtVerify } from 'jose'
import type { Adapter, Session } from 'oidcraft'
import type { UpstreamProvider } from './types'

export type UpstreamLogout = {
  provider: string
  /** Sessions this OP issued off the back of the upstream one that just ended. */
  sessions: Session[]
}

/**
 * Handles a back-channel logout token from an upstream (FR-F8).
 *
 * The token arrives keyed by the *upstream's* session id, which is why `SessionStore` records it:
 * without that index there is no way back from "their session ended" to "these are ours".
 */
export const upstreamLogout = async (
  adapter: Adapter,
  provider: UpstreamProvider,
  logoutToken: string,
  jwks: JSONWebKeySet
): Promise<UpstreamLogout> => {
  const { payload } = await jwtVerify(logoutToken, createLocalJWKSet(jwks), {
    issuer: provider.issuer,
    audience: provider.clientId
  })

  // OIDC Back-Channel Logout 1.0 §2.4: the events claim is what distinguishes a logout token from
  // an ID token, and accepting one without it would let a replayed ID token end sessions.
  const events = payload.events as Record<string, unknown> | undefined
  if (!events || !('http://schemas.openid.net/event/backchannel-logout' in events)) {
    throw new Error('this is not a logout token: it carries no back-channel logout event')
  }
  if ('nonce' in payload) throw new Error('a logout token must not carry a nonce (OIDC Back-Channel Logout 1.0 §2.4)')

  const sid = typeof payload.sid === 'string' ? payload.sid : undefined
  const sub = typeof payload.sub === 'string' ? payload.sub : undefined
  if (!sid && !sub) throw new Error('a logout token needs sid or sub')

  const sessions = sid
    ? ((await adapter.sessions.findByUpstreamSession?.(provider.id, sid)) ?? [])
    : await sessionsForUpstreamSubject(adapter, provider.id, sub as string)

  return { provider: provider.id, sessions }
}

const sessionsForUpstreamSubject = async (adapter: Adapter, providerId: string, subject: string) => {
  const identity = await adapter.identities?.find(providerId, subject)
  if (!identity) return []
  const sessions = await adapter.sessions.findByAccount(identity.accountId)
  return sessions.filter(session => session.idp === providerId)
}

/** Reads the upstream a logout token came from, before it is trusted, so the right keys are used. */
export const issuerOf = (logoutToken: string) => {
  try {
    return decodeJwt(logoutToken).iss as string | undefined
  } catch {
    return undefined
  }
}
