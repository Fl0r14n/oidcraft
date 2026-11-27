import type { Client } from '@oidcraft/adapter'
import { randomString } from '@oidcraft/core'
import { verifyChallenge } from '../authorize/pkce'
import { audienceFor, requestedResources } from '../authorize/resources'
import type { ResolvedConfig } from '../config'
import { OAuthError } from '../errors'
import { readArtifact } from '../payloads'
import { type Binding, issueTokens, loadGrantAndSession } from './issue'
import { revokeOnReplay, unlessReplayed } from './replay'

export const redeemAuthorizationCode = async (config: ResolvedConfig, client: Client, form: URLSearchParams, binding: Binding) => {
  const code = form.get('code')
  if (!code) throw new OAuthError('invalid_request', { description: 'code is required', spec: 'RFC 6749 §4.1.3' })

  const artifact = await readArtifact(config.adapter.artifacts, 'authorization_code', code)
  if (!artifact)
    throw new OAuthError('invalid_grant', { description: 'the authorization code is unknown or expired', spec: 'RFC 6749 §5.2' })
  if (artifact.consumedAt) await revokeOnReplay(config, artifact, 'authorization code', client.clientId)

  // The code was issued to one client; another presenting it is theft, not a mistake.
  if (artifact.clientId !== client.clientId) {
    await revokeOnReplay(config, artifact, 'authorization code presented by the wrong client', client.clientId)
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
  const audience = audienceFor(requestedResources(config, form, client.clientId), artifact.payload.resources ?? [])
  // The read above can be stale by now; only the atomic consume decides who redeemed it (NFR-S4).
  if (!(await config.adapter.artifacts.consume('authorization_code', code)))
    await revokeOnReplay(config, artifact, 'authorization code', client.clientId)

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
  return unlessReplayed(config, artifact, 'authorization code', tokens)
}
