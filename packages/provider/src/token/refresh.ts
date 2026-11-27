import type { Client } from '@oidcraft/adapter'
import { randomString } from '@oidcraft/core'
import { stillConsented } from '../authorize/claims'
import { audienceFor, requestedResources } from '../authorize/resources'
import type { ResolvedConfig } from '../config'
import { OAuthError } from '../errors'
import { readArtifact, writeArtifact } from '../payloads'
import { underFapi } from '../profile/fapi'
import { assertBoundTo } from './access-token'
import { familyOf } from './family'
import { type Binding, issueTokens, loadGrantAndSignIn } from './issue'
import { revokeOnReplay, unlessReplayed } from './replay'

export const redeemRefreshToken = async (config: ResolvedConfig, client: Client, form: URLSearchParams, binding: Binding) => {
  const presented = form.get('refresh_token')
  if (!presented) throw new OAuthError('invalid_request', { description: 'refresh_token is required', spec: 'RFC 6749 §6' })

  const artifact = await readArtifact(config.adapter.artifacts, 'refresh_token', presented)
  if (!artifact) throw new OAuthError('invalid_grant', { description: 'the refresh token is unknown or expired', spec: 'RFC 6749 §5.2' })
  if (artifact.consumedAt) await revokeOnReplay(config, artifact, 'refresh token', client.clientId)
  if (artifact.clientId !== client.clientId)
    await revokeOnReplay(config, artifact, 'refresh token presented by the wrong client', client.clientId)
  const family = familyOf(artifact.payload)
  // NFR-D6: written before the family had an absolute end; read without one, every rotation would start the clock again.
  if (!family) {
    throw new OAuthError('invalid_grant', { description: 'this refresh token predates its family lifetime; sign in again', spec: 'NFR-D6' })
  }

  const { grant, session } = await loadGrantAndSignIn(config, artifact)
  const requested = form.get('scope')?.split(' ').filter(Boolean)
  // FR-I4: consent withdrawn from the grant since this token was issued does not come back on refresh.
  const granted = artifact.payload.scopes.filter(scope => grant.scopes.includes(scope))
  // RFC 6749 §6: a refresh may narrow the scope, never widen it.
  const widened = requested?.filter(scope => !granted.includes(scope)) ?? []
  if (widened.length)
    throw new OAuthError('invalid_scope', { description: `a refresh cannot add scopes: ${widened.join(', ')}`, spec: 'RFC 6749 §6' })
  const audience = audienceFor(requestedResources(config, form, client.clientId), artifact.payload.resources ?? [])

  // A bound refresh token may only be presented by the key it was bound to (RFC 9449 §5).
  const bound = artifact.payload.cnf
  assertBoundTo(bound, binding, 'this refresh token')

  // FR-T3: always rotate, save a FAPI client, whose token is useless without its key (FAPI 2.0 Security Profile §5.3.2.1).
  const rotate = !underFapi(config, client)
  if (rotate && !(await config.adapter.artifacts.consume('refresh_token', presented))) {
    await revokeOnReplay(config, artifact, 'refresh token', client.clientId)
  }

  // FR-T3: a token that does not rotate still restarts its idle lifetime, within its family's and its session's.
  if (!rotate) {
    const sessionEnd = artifact.payload.sessionBound === true ? session.expiresAt : Number.POSITIVE_INFINITY
    const expiresAt = Math.min(Date.now() + config.ttl.refreshToken * 1000, family.expiresAt, sessionEnd)
    await writeArtifact(config.adapter.artifacts, { ...artifact, expiresAt })
  }

  // RFC 8705 §3: the new access token is bound to the certificate presented now, as at issuance.
  const familyId = artifact.familyId ?? randomString()
  const tokens = await issueTokens(config, client, grant, session, requested?.length ? requested : granted, {
    familyId,
    binding: { jkt: bound?.jkt ?? binding.jkt, x5t: binding.x5t },
    refreshScopes: granted,
    sessionBound: artifact.payload.sessionBound === true,
    ...(!rotate && { keepRefreshToken: presented }),
    family,
    audience,
    resources: artifact.payload.resources ?? [],
    claims: stillConsented(config, grant, artifact.payload.claims, requested?.length ? requested : granted)
  })
  return rotate ? unlessReplayed(config, artifact, 'refresh token', tokens) : tokens
}
