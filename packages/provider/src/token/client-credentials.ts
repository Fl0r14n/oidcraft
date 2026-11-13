import type { Client } from '@oidcraft/adapter'
import { audienceFor, requestedResources } from '../authorize/resources'
import type { ResolvedConfig } from '../config'
import { OAuthError } from '../errors'
import { type Binding, issueAccessToken } from './access-token'

// RFC 6749 §4.4: no user, so no ID token, no refresh token (§4.4.3) and no `openid`.
export const clientCredentialsGrant = async (config: ResolvedConfig, client: Client, form: URLSearchParams, binding: Binding) => {
  if (client.tokenEndpointAuthMethod === 'none') {
    throw new OAuthError('invalid_client', {
      description: 'a public client has no credentials of its own to present',
      spec: 'RFC 6749 §4.4'
    })
  }

  const requested = (form.get('scope') ?? '').split(' ').filter(Boolean)
  if (requested.includes('openid')) {
    throw new OAuthError('invalid_scope', {
      description: 'client_credentials identifies no user, so openid is meaningless here',
      spec: 'RFC 6749 §3.3'
    })
  }
  const unallowed = requested.filter(scope => !client.scopes.includes(scope))
  if (unallowed.length)
    throw new OAuthError('invalid_scope', {
      description: `client ${client.clientId} may not request: ${unallowed.join(', ')}`,
      spec: 'RFC 6749 §3.3'
    })

  const scopes = requested.length ? requested : client.scopes.filter(scope => scope !== 'openid' && scope !== 'offline_access')
  // No user consented to anything, so any configured resource may be named (FR-C19).
  const audience = audienceFor(requestedResources(config, form), [])
  const access = await issueAccessToken(config, { client, scopes, binding, audience })
  return { access_token: access.token, token_type: access.tokenType, expires_in: access.expiresIn, scope: scopes.join(' ') }
}
