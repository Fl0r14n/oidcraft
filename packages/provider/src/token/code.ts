import type { Client } from '@oidcraft/adapter'
import { randomString } from '@oidcraft/core'
import { storedId } from '../artifacts'
import { verifyChallenge } from '../authorize/pkce'
import { audienceFor, requestedResources } from '../authorize/resources'
import type { ResolvedConfig } from '../config'
import { OAuthError } from '../errors'
import { readArtifact, type Stored, writeArtifact } from '../payloads'

type SingleUse = Stored<'authorization_code' | 'refresh_token'>

import { stillConsented } from '../authorize/claims'
import { underFapi } from '../profile/fapi'
import { assertFamilyLive, revokeFamily } from './family'
import { type Binding, issueTokens, loadGrantAndSession, loadGrantAndSignIn } from './issue'

// A replay means it leaked: revoke its family, not the grant's others (FR-T3, FR-T4, NFR-S4, RFC 9700 §4.14.2).
const revokeOnReplay = async (config: ResolvedConfig, artifact: SingleUse, what: string) => {
  await replayed(config, artifact)
  await revokeFamily(config, artifact)
  throw new OAuthError('invalid_grant', {
    description: `this ${what} was already used; every token issued from it has been revoked`,
    spec: 'RFC 9700 §4.14.2',
    event: {
      action: 'token.replay',
      clientId: artifact.clientId,
      ...(artifact.accountId && { accountId: artifact.accountId }),
      ...(artifact.grantId && { grantId: artifact.grantId }),
      detail: { kind: artifact.kind, ...(artifact.familyId && { familyId: artifact.familyId }) }
    }
  })
}

/** How long a replay is remembered: longer than any redemption takes to write its tokens. */
const REPLAY_WINDOW = 60

// A replay claims this before revoking, the winner after writing; `false` for the winner means the revocation missed its tokens.
const replayed = async (config: ResolvedConfig, artifact: SingleUse) =>
  !(await config.adapter.replay.claim('redeemed', await storedId(`${artifact.kind}:${artifact.id}`), REPLAY_WINDOW))

/** NFR-S4: tokens written after a concurrent replay revoked the family must not outlive it. */
const unlessReplayed = async <T>(config: ResolvedConfig, artifact: SingleUse, what: string, tokens: T) => {
  if (await replayed(config, artifact)) await revokeOnReplay(config, artifact, what)
  return tokens
}

export const authorizationCodeGrant = async (config: ResolvedConfig, client: Client, form: URLSearchParams, binding: Binding) => {
  const code = form.get('code')
  if (!code) throw new OAuthError('invalid_request', { description: 'code is required', spec: 'RFC 6749 §4.1.3' })

  const artifact = await readArtifact(config.adapter.artifacts, 'authorization_code', code)
  if (!artifact)
    throw new OAuthError('invalid_grant', { description: 'the authorization code is unknown or expired', spec: 'RFC 6749 §5.2' })
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

  // RFC 9449 §10: checked before the consume, so a thief's attempt does not burn the client's code.
  const { dpopJkt } = artifact.payload
  if (dpopJkt && binding.jkt !== dpopJkt) {
    throw new OAuthError('invalid_grant', {
      description: binding.jkt
        ? 'this authorization code is bound to a different DPoP key'
        : 'this authorization code is bound to a DPoP key; present a proof made with it',
      spec: 'RFC 9449 §10'
    })
  }

  await verifyChallenge(form.get('code_verifier'), artifact.payload.codeChallenge)
  const audience = audienceFor(requestedResources(config, form), artifact.payload.resources ?? [])
  // The read above can be stale by now; only the atomic consume decides who redeemed it (NFR-S4).
  if (!(await config.adapter.artifacts.consume('authorization_code', code))) await revokeOnReplay(config, artifact, 'authorization code')

  const { grant, session } = await loadGrantAndSession(config, artifact)
  const familyId = artifact.familyId ?? randomString()
  const tokens = await issueTokens(config, client, grant, session, artifact.payload.scopes, {
    familyId,
    nonce: artifact.payload.nonce,
    binding,
    authorizationDetails: artifact.payload.authorizationDetails,
    sessionBound: true,
    audience,
    resources: artifact.payload.resources ?? [],
    claims: artifact.payload.claims
  })
  await assertFamilyLive(config, familyId, grant.id)
  return unlessReplayed(config, artifact, 'authorization code', tokens)
}

export const refreshTokenGrant = async (config: ResolvedConfig, client: Client, form: URLSearchParams, binding: Binding) => {
  const presented = form.get('refresh_token')
  if (!presented) throw new OAuthError('invalid_request', { description: 'refresh_token is required', spec: 'RFC 6749 §6' })

  const artifact = await readArtifact(config.adapter.artifacts, 'refresh_token', presented)
  if (!artifact) throw new OAuthError('invalid_grant', { description: 'the refresh token is unknown or expired', spec: 'RFC 6749 §5.2' })
  if (artifact.consumedAt) await revokeOnReplay(config, artifact, 'refresh token')
  if (artifact.clientId !== client.clientId) await revokeOnReplay(config, artifact, 'refresh token presented by the wrong client')

  const { grant, session } = await loadGrantAndSignIn(config, artifact)
  const requested = form.get('scope')?.split(' ').filter(Boolean)
  // FR-I4: consent withdrawn from the grant since this token was issued does not come back on refresh.
  const granted = artifact.payload.scopes.filter(scope => grant.scopes.includes(scope))
  // RFC 6749 §6: a refresh may narrow the scope, never widen it.
  const widened = requested?.filter(scope => !granted.includes(scope)) ?? []
  if (widened.length)
    throw new OAuthError('invalid_scope', { description: `a refresh cannot add scopes: ${widened.join(', ')}`, spec: 'RFC 6749 §6' })
  const audience = audienceFor(requestedResources(config, form), artifact.payload.resources ?? [])

  // A bound refresh token may only be presented by the key it was bound to (RFC 9449 §5).
  const bound = artifact.payload.cnf
  if (bound?.jkt && bound.jkt !== binding.jkt) {
    throw new OAuthError('invalid_grant', { description: 'this refresh token is bound to a different key', spec: 'RFC 9449 §5' })
  }
  if (bound?.['x5t#S256'] && bound['x5t#S256'] !== binding.x5t) {
    throw new OAuthError('invalid_grant', { description: 'this refresh token is bound to a different certificate', spec: 'RFC 8705 §4' })
  }

  // FR-T3: always rotate, save a FAPI client, whose token is useless without its key (FAPI 2.0 Security Profile §5.3.2.1).
  const rotate = !underFapi(config, client)
  if (rotate && !(await config.adapter.artifacts.consume('refresh_token', presented))) {
    await revokeOnReplay(config, artifact, 'refresh token')
  }

  // FR-T3: a token that does not rotate still restarts its idle lifetime, within its family's and its session's.
  if (!rotate) {
    const familyEnd = artifact.payload.familyExpiresAt * 1000
    const sessionEnd = artifact.payload.sessionBound === true ? session.expiresAt.getTime() : Number.POSITIVE_INFINITY
    const expiresAt = new Date(Math.min(Date.now() + config.ttl.refreshToken * 1000, familyEnd, sessionEnd))
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
    familyExpiresAt: artifact.payload.familyExpiresAt,
    audience,
    resources: artifact.payload.resources ?? [],
    claims: stillConsented(config, grant, artifact.payload.claims, requested?.length ? requested : granted)
  })
  // RFC 9700 §4.14.2: a revocation that raced this refresh, the FAPI rewrite included, is not undone by it.
  await assertFamilyLive(config, familyId, grant.id)
  return rotate ? unlessReplayed(config, artifact, 'refresh token', tokens) : tokens
}
