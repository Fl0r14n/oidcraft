import { authenticateClient } from '../client-auth'
import type { ResolvedConfig } from '../config'
import { OAuthError } from '../errors'
import type { Artifact, ArtifactKind } from '../types'

const INTROSPECTABLE: ArtifactKind[] = ['access_token', 'refresh_token']

const seconds = (date: Date) => Math.floor(date.getTime() / 1000)

const describe = (artifact: Artifact, kind: ArtifactKind, issuer: string) => ({
  active: true,
  scope: ((artifact.payload.scopes as string[] | undefined) ?? []).join(' '),
  client_id: artifact.clientId,
  token_type: kind === 'access_token' ? 'Bearer' : undefined,
  exp: seconds(artifact.expiresAt),
  iat: seconds(new Date(artifact.expiresAt.getTime())),
  sub: artifact.accountId,
  aud: artifact.clientId,
  iss: issuer
})

/**
 * RFC 7662 §2.2: a token the caller may not see is `active: false`, never an error — the difference
 * between "expired" and "belongs to someone else" is exactly what an attacker wants to learn.
 */
export const introspectionEndpoint = async (config: ResolvedConfig, request: Request) => {
  const form = new URLSearchParams(await request.text())
  const { client } = await authenticateClient(config, form, request.headers)

  const presented = form.get('token')
  if (!presented) throw new OAuthError('invalid_request', { description: 'token is required', spec: 'RFC 7662 §2.1' })

  const inactive = Response.json({ active: false }, { headers: { 'cache-control': 'no-store' } })
  const hint = form.get('token_type_hint')
  const kinds = hint === 'refresh_token' ? ['refresh_token', 'access_token'] : INTROSPECTABLE

  for (const kind of kinds as ArtifactKind[]) {
    const artifact = await config.adapter.artifacts.find(kind, presented)
    if (!artifact || artifact.consumedAt) continue
    if (artifact.clientId !== client.clientId) return inactive

    const body = describe(artifact, kind, config.issuer)
    return Response.json(Object.fromEntries(Object.entries(body).filter(([, value]) => value !== undefined)), {
      headers: { 'cache-control': 'no-store' }
    })
  }

  return inactive
}
