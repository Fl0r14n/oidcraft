import { authenticateClient } from '../client-auth'
import type { ResolvedConfig } from '../config'
import { OAuthError } from '../errors'
import type { ArtifactKind } from '../types'

const REVOCABLE: ArtifactKind[] = ['refresh_token', 'access_token']

const order = (hint: string | null) => (hint === 'access_token' ? (['access_token', 'refresh_token'] as ArtifactKind[]) : REVOCABLE)

/**
 * RFC 7009 §2.2: an unknown token is a 200, not an error. Anything else turns this endpoint into an
 * oracle for guessing which tokens exist. The same reasoning applies to a token belonging to
 * someone else — it is reported as success and nothing is revoked.
 */
export const revocationEndpoint = async (config: ResolvedConfig, request: Request) => {
  const form = new URLSearchParams(await request.text())
  const { client } = await authenticateClient(config, form, request.headers)

  const presented = form.get('token')
  if (!presented) throw new OAuthError('invalid_request', { description: 'token is required', spec: 'RFC 7009 §2.1' })

  const ok = new Response(null, { status: 200, headers: { 'cache-control': 'no-store' } })

  for (const kind of order(form.get('token_type_hint'))) {
    const artifact = await config.adapter.artifacts.find(kind, presented)
    if (!artifact || artifact.clientId !== client.clientId) continue

    // Revoking a refresh token takes the whole grant with it: leaving the access tokens it minted
    // alive would make "sign this application out" mean nothing for their remaining lifetime.
    if (kind === 'refresh_token' && artifact.grantId) {
      await config.adapter.artifacts.revokeByGrantId(artifact.grantId)
      await config.adapter.grants.destroy(artifact.grantId)
    } else {
      await config.adapter.artifacts.destroy(kind, presented)
    }
    return ok
  }

  return ok
}
