import type { Client } from '@oidcraft/adapter'
import { authenticateClient } from '../clients/authenticate'
import type { ResolvedConfig } from '../config'
import type { ClientCertificate } from '../context'
import type { Caller } from '../cors'
import { OAuthError } from '../errors'
import type { Stored } from '../payloads'
import { findPresented } from '../token/access-token'
import { subjectFor } from '../token/subjects'

type Token = Stored<'access_token' | 'refresh_token'>

const INTROSPECTABLE: Token['kind'][] = ['access_token', 'refresh_token']

const seconds = (date: Date) => Math.floor(date.getTime() / 1000)

const accessPayload = (artifact: Token) => (artifact.kind === 'access_token' ? artifact.payload : undefined)

const describe = (artifact: Token, issuer: string, subject: string | undefined) => {
  const access = accessPayload(artifact)
  return {
    active: true,
    scope: artifact.payload.scopes.join(' '),
    client_id: artifact.clientId,
    token_type: access ? (access.cnf ? 'DPoP' : 'Bearer') : undefined,
    exp: seconds(artifact.expiresAt),
    iat: artifact.payload.iat,
    sub: subject,
    aud: access?.aud ?? artifact.clientId,
    iss: issuer,
    // A resource server must be able to see the binding, or it cannot enforce it (RFC 9449 §6).
    cnf: artifact.payload.cnf
  }
}

/** Audiences a token was restricted to by exchange (RFC 8693) or a resource indicator (RFC 8707). */
const audiencesOf = (artifact: Token) => {
  const access = accessPayload(artifact)
  return [access?.aud, access?.resource].filter((value): value is string => value !== undefined)
}

/**
 * The token's own client may always ask. Of access tokens — a refresh token is never presented to a
 * resource — the server a configured resource names may ask about those issued for that resource,
 * and nothing else (FR-C19); a client flagged `resourceServer` about any not restricted to some other
 * audience (FR-C8).
 */
const mayIntrospect = (config: ResolvedConfig, client: Client, artifact: Token) => {
  if (artifact.clientId === client.clientId) return true
  if (artifact.kind !== 'access_token') return false
  const audiences = audiencesOf(artifact)
  const served = config.resources.filter(resource => resource.resourceServer === client.clientId).map(resource => resource.uri)
  if (audiences.some(audience => served.includes(audience))) return true
  if (!client.resourceServer) return false
  return audiences.length === 0 || audiences.includes(client.clientId)
}

/**
 * RFC 7662 §2.2: a token the caller may not see is `active: false`, never an error — the difference
 * between "expired" and "belongs to someone else" is exactly what an attacker wants to learn.
 */
export const introspectionEndpoint = async (
  config: ResolvedConfig,
  request: Request,
  certificate?: ClientCertificate | undefined,
  caller: Caller = {}
) => {
  const form = new URLSearchParams(await request.text())
  const { client } = await authenticateClient(config, form, request.headers, certificate, caller)

  const presented = form.get('token')
  if (!presented) throw new OAuthError('invalid_request', { description: 'token is required', spec: 'RFC 7662 §2.1' })

  const inactive = Response.json({ active: false }, { headers: { 'cache-control': 'no-store' } })
  const hint = form.get('token_type_hint')
  const kinds: Token['kind'][] = hint === 'refresh_token' ? ['refresh_token', 'access_token'] : INTROSPECTABLE

  for (const kind of kinds) {
    const artifact = await findPresented(config, kind, presented)
    if (!artifact || artifact.consumedAt) continue
    if (!mayIntrospect(config, client, artifact)) return inactive

    // FR-C18: the subject the token's client was given, never the account id behind a pairwise one.
    const owner = artifact.clientId === client.clientId ? client : await config.adapter.clients.find(artifact.clientId)
    const subject =
      artifact.accountId && owner ? (accessPayload(artifact)?.subject ?? (await subjectFor(config, owner, artifact.accountId))) : undefined
    const body = describe(artifact, config.issuer, subject)
    return Response.json(Object.fromEntries(Object.entries(body).filter(([, value]) => value !== undefined)), {
      headers: { 'cache-control': 'no-store' }
    })
  }

  return inactive
}
