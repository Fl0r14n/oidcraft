import { authenticateClient } from '../clients/authenticate'
import type { ResolvedConfig } from '../config'
import type { ClientCertificate } from '../context'
import { OAuthError } from '../errors'
import { findPresented } from '../token/access-token'
import { subjectFor } from '../token/subjects'
import type { Artifact, ArtifactKind, Client } from '../types'

const INTROSPECTABLE: ArtifactKind[] = ['access_token', 'refresh_token']

const seconds = (date: Date) => Math.floor(date.getTime() / 1000)

const describe = (artifact: Artifact, kind: ArtifactKind, issuer: string, subject: string | undefined) => ({
  active: true,
  scope: ((artifact.payload.scopes as string[] | undefined) ?? []).join(' '),
  client_id: artifact.clientId,
  token_type: kind === 'access_token' ? (artifact.payload.cnf ? 'DPoP' : 'Bearer') : undefined,
  exp: seconds(artifact.expiresAt),
  iat: typeof artifact.payload.iat === 'number' ? artifact.payload.iat : undefined,
  sub: subject,
  aud: (artifact.payload.aud as string | undefined) ?? artifact.clientId,
  iss: issuer,
  // A resource server must be able to see the binding, or it cannot enforce it (RFC 9449 §6).
  cnf: artifact.payload.cnf as { jkt: string } | undefined
})

/** Audiences a token was restricted to by exchange (RFC 8693) or a resource indicator (RFC 8707). */
const audiencesOf = (artifact: Artifact) =>
  [artifact.payload.aud, artifact.payload.resource].filter((value): value is string => typeof value === 'string')

/**
 * The token's own client may always ask. A resource server may ask about access tokens — a refresh
 * token is never presented to it — unless the token was restricted to some other audience (FR-C8).
 */
const mayIntrospect = (client: Client, artifact: Artifact, kind: ArtifactKind) => {
  if (artifact.clientId === client.clientId) return true
  if (!client.resourceServer || kind !== 'access_token') return false
  const audiences = audiencesOf(artifact)
  return audiences.length === 0 || audiences.includes(client.clientId)
}

/**
 * RFC 7662 §2.2: a token the caller may not see is `active: false`, never an error — the difference
 * between "expired" and "belongs to someone else" is exactly what an attacker wants to learn.
 */
export const introspectionEndpoint = async (config: ResolvedConfig, request: Request, certificate?: ClientCertificate | undefined) => {
  const form = new URLSearchParams(await request.text())
  const { client } = await authenticateClient(config, form, request.headers, certificate)

  const presented = form.get('token')
  if (!presented) throw new OAuthError('invalid_request', { description: 'token is required', spec: 'RFC 7662 §2.1' })

  const inactive = Response.json({ active: false }, { headers: { 'cache-control': 'no-store' } })
  const hint = form.get('token_type_hint')
  const kinds = hint === 'refresh_token' ? ['refresh_token', 'access_token'] : INTROSPECTABLE

  for (const kind of kinds as ArtifactKind[]) {
    const artifact = await findPresented(config, kind, presented)
    if (!artifact || artifact.consumedAt) continue
    if (!mayIntrospect(client, artifact, kind)) return inactive

    // FR-C18: the subject the token's client was given, never the account id behind a pairwise one.
    const owner = artifact.clientId === client.clientId ? client : await config.adapter.clients.find(artifact.clientId)
    const subject =
      artifact.accountId && owner
        ? ((artifact.payload.subject as string | undefined) ?? (await subjectFor(config, owner, artifact.accountId)))
        : undefined
    const body = describe(artifact, kind, config.issuer, subject)
    return Response.json(Object.fromEntries(Object.entries(body).filter(([, value]) => value !== undefined)), {
      headers: { 'cache-control': 'no-store' }
    })
  }

  return inactive
}
