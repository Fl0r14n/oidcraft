import type { Session } from '@oidcraft/adapter'
import { randomString } from '@oidcraft/core'
import type { ResolvedConfig } from '../config'
import { signerFor } from '../keys/signer'
import { subjectFor } from '../token/subjects'

export type LogoutNotification = { clientId: string; uri: string; logoutToken: string }

/** A URL the host loads in an iframe (OIDC Front-Channel Logout 1.0 §2). */
export type FrontChannelLogout = { clientId: string; uri: string }

// URLs, never HTML (FR-C11); `iss` and `sid` go only to a client that asked, or the session id leaks (§2).
export const frontChannelLogouts = async (config: ResolvedConfig, session: Session): Promise<FrontChannelLogout[]> => {
  const out: FrontChannelLogout[] = []
  for (const clientId of session.clients) {
    const client = await config.adapter.clients.find(clientId)
    // One stored URI that does not parse must not keep the others, or the logout, from happening.
    if (!client?.frontchannelLogoutUri || !URL.canParse(client.frontchannelLogoutUri)) continue
    const uri = new URL(client.frontchannelLogoutUri)
    if (client.frontchannelLogoutSessionRequired) {
      uri.searchParams.set('iss', config.issuer)
      uri.searchParams.set('sid', session.id)
    }
    out.push({ clientId, uri: uri.toString() })
  }
  return out
}

const LOGOUT_TOKEN_TTL = 120

// Minted, never POSTed: delivery is the host's (FR-A1, OIDC Back-Channel Logout 1.0 §2.4).
export const logoutTokens = async (config: ResolvedConfig, session: Session): Promise<LogoutNotification[]> => {
  const notifications: LogoutNotification[] = []
  for (const clientId of session.clients) {
    const client = await config.adapter.clients.find(clientId)
    if (!client?.backchannelLogoutUri) continue
    // OIDC Back-Channel Logout 1.0 §2.4: signed as this client's ID tokens are, which is what it verifies with.
    const signer = await signerFor(config, client, client.idTokenSignedResponseAlg)
    if (!signer) continue

    const now = Math.floor(Date.now() / 1000)
    const logoutToken = await signer.sign(
      {
        // FR-C18: the subject this client knows, never the account id behind a pairwise one.
        sub: await subjectFor(config, client, session.accountId),
        aud: clientId,
        iat: now,
        exp: now + LOGOUT_TOKEN_TTL,
        sid: session.id,
        // The marker that makes this a logout token and not a re-usable ID token (§2.4).
        events: { 'http://schemas.openid.net/event/backchannel-logout': {} },
        jti: randomString()
      },
      'logout+jwt'
    )

    notifications.push({ clientId, uri: client.backchannelLogoutUri, logoutToken })
  }
  return notifications
}
