import { randomString } from '@oidcraft/core'
import { importJWK, SignJWT } from 'jose'
import type { ResolvedConfig } from '../config'
import { signingKey } from '../keys/keys'
import { defaultSigningAlg } from '../profile/fapi'
import { subjectFor } from '../token/subjects'
import type { Session } from '../types'

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
  const alg = defaultSigningAlg(config, undefined, keys)
  const key = alg ? signingKey(keys, alg) : undefined
  if (!key || !alg) return []

  const notifications: LogoutNotification[] = []
  for (const clientId of session.clients) {
    const client = await config.adapter.clients.find(clientId)
    if (!client?.backchannelLogoutUri) continue

    const logoutToken = await new SignJWT({
      // FR-C18: the subject this client knows, never the account id behind a pairwise one.
      sub: await subjectFor(config, client, session.accountId),
      sid: session.id,
      // The marker that makes this a logout token and not a re-usable ID token (§2.4).
      events: { 'http://schemas.openid.net/event/backchannel-logout': {} },
      jti: randomString()
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
