import { verifyChallenge } from '../authorize/pkce'
import type { ResolvedConfig } from '../config'
import { OAuthError } from '../errors'
import type { Artifact, Client } from '../types'
import { type Binding, issueTokens, loadGrantAndSession } from './issue'

/**
 * Replaying a single-use artifact revokes the grant it belongs to, rather than merely failing.
 * A replay means the code or refresh token leaked; everything derived from it must stop working
 * (FR-T3, FR-T4, NFR-S4, RFC 9700 §4.14.2).
 */
const revokeOnReplay = async (config: ResolvedConfig, artifact: Artifact, what: string) => {
  if (artifact.grantId) await config.adapter.artifacts.revokeByGrantId(artifact.grantId)
  throw new OAuthError('invalid_grant', {
    description: `this ${what} was already used; the grant has been revoked`,
    spec: 'RFC 9700 §4.14.2'
  })
}

const scopesOf = (artifact: Artifact) => (artifact.payload.scopes as string[] | undefined) ?? []

export const authorizationCodeGrant = async (config: ResolvedConfig, client: Client, form: URLSearchParams, binding: Binding) => {
  const code = form.get('code')
  if (!code) throw new OAuthError('invalid_request', { description: 'code is required' })

  const artifact = await config.adapter.artifacts.find('authorization_code', code)
  if (!artifact) throw new OAuthError('invalid_grant', { description: 'the authorization code is unknown or expired' })
  if (artifact.consumedAt) await revokeOnReplay(config, artifact, 'authorization code')

  // The code was issued to one client; another presenting it is theft, not a mistake.
  if (artifact.clientId !== client.clientId) {
    await revokeOnReplay(config, artifact, 'authorization code presented by the wrong client')
  }

  const redirectUri = form.get('redirect_uri')
  if (redirectUri !== artifact.payload.redirectUri) {
    throw new OAuthError('invalid_grant', {
      description: 'redirect_uri does not match the one the code was issued for',
      spec: 'RFC 6749 §4.1.3'
    })
  }

  await verifyChallenge(form.get('code_verifier'), artifact.payload.codeChallenge as string | undefined)
  // The read above can be stale by now; only the atomic consume decides who redeemed it (NFR-S4).
  if (!(await config.adapter.artifacts.consume('authorization_code', code))) await revokeOnReplay(config, artifact, 'authorization code')

  const { grant, session } = await loadGrantAndSession(config, artifact)
  return issueTokens(config, client, grant, session, scopesOf(artifact), {
    nonce: artifact.payload.nonce as string | undefined,
    binding,
    authorizationDetails: artifact.payload.authorizationDetails as unknown[] | undefined
  })
}

export const refreshTokenGrant = async (config: ResolvedConfig, client: Client, form: URLSearchParams, binding: Binding) => {
  const presented = form.get('refresh_token')
  if (!presented) throw new OAuthError('invalid_request', { description: 'refresh_token is required' })

  const artifact = await config.adapter.artifacts.find('refresh_token', presented)
  if (!artifact) throw new OAuthError('invalid_grant', { description: 'the refresh token is unknown or expired' })
  if (artifact.consumedAt) await revokeOnReplay(config, artifact, 'refresh token')
  if (artifact.clientId !== client.clientId) await revokeOnReplay(config, artifact, 'refresh token presented by the wrong client')

  const { grant, session } = await loadGrantAndSession(config, artifact)
  const requested = form.get('scope')?.split(' ').filter(Boolean)
  // FR-I4: consent withdrawn from the grant since this token was issued does not come back on refresh.
  const granted = scopesOf(artifact).filter(scope => grant.scopes.includes(scope))
  // RFC 6749 §6: a refresh may narrow the scope, never widen it.
  const widened = requested?.filter(scope => !granted.includes(scope)) ?? []
  if (widened.length) throw new OAuthError('invalid_scope', { description: `a refresh cannot add scopes: ${widened.join(', ')}` })

  // A bound refresh token may only be presented by the key it was bound to (RFC 9449 §5).
  const bound = artifact.payload.cnf as { jkt?: string; 'x5t#S256'?: string } | undefined
  if (bound?.jkt && bound.jkt !== binding.jkt) {
    throw new OAuthError('invalid_grant', { description: 'this refresh token is bound to a different key', spec: 'RFC 9449 §5' })
  }
  if (bound?.['x5t#S256'] && bound['x5t#S256'] !== binding.x5t) {
    throw new OAuthError('invalid_grant', { description: 'this refresh token is bound to a different certificate', spec: 'RFC 8705 §4' })
  }

  // FR-T3: rotation is unconditional, which is what makes the replay rule above meaningful.
  if (!(await config.adapter.artifacts.consume('refresh_token', presented))) await revokeOnReplay(config, artifact, 'refresh token')

  // RFC 8705 §3: the new access token is bound to the certificate presented now, as at issuance.
  return issueTokens(config, client, grant, session, requested?.length ? requested : granted, {
    binding: { jkt: bound?.jkt ?? binding.jkt, x5t: binding.x5t },
    refreshScopes: granted
  })
}
