import type { ResolvedConfig } from '../config'
import { OAuthError } from '../errors'
import type { Client } from '../types'
import { type Binding, issueAccessToken } from './access-token'

/**
 * The client acting as itself, with no user behind it (RFC 6749 §4.4).
 *
 * So: no ID token, because there is no subject to make claims about; no refresh token, because the
 * client can simply ask again with the credentials it still holds (§4.4.3); and `openid` is refused,
 * because a scope that means "tell me who the user is" is meaningless when there is no user.
 */
export const clientCredentialsGrant = async (config: ResolvedConfig, client: Client, form: URLSearchParams, binding: Binding) => {
  if (client.tokenEndpointAuthMethod === 'none') {
    throw new OAuthError('invalid_client', {
      description: 'a public client has no credentials of its own to present',
      spec: 'RFC 6749 §4.4'
    })
  }

  const requested = (form.get('scope') ?? '').split(' ').filter(Boolean)
  if (requested.includes('openid')) {
    throw new OAuthError('invalid_scope', { description: 'client_credentials identifies no user, so openid is meaningless here' })
  }
  const unallowed = requested.filter(scope => !client.scopes.includes(scope))
  if (unallowed.length)
    throw new OAuthError('invalid_scope', { description: `client ${client.clientId} may not request: ${unallowed.join(', ')}` })

  const scopes = requested.length ? requested : client.scopes.filter(scope => scope !== 'openid' && scope !== 'offline_access')
  const access = await issueAccessToken(config, { client, scopes, binding })
  return { access_token: access.token, token_type: access.tokenType, expires_in: access.expiresIn, scope: scopes.join(' ') }
}
