import type { ResolvedConfig } from '../config'
import { OAuthError } from '../errors'
import { token } from '../random'
import type { Client, ClientAuthMethod } from '../types'

const DEFAULT_GRANTS = ['authorization_code']
const DEFAULT_RESPONSE_TYPES = ['code']

const invalid = (description: string, code: 'invalid_client_metadata' | 'invalid_redirect_uri' = 'invalid_client_metadata') =>
  new OAuthError('invalid_request', { description, spec: `OIDC Dynamic Client Registration 1.0 §3.3 (${code})`, status: 400 })

const isLoopback = (url: URL) => url.hostname === 'localhost' || url.hostname === '127.0.0.1' || url.hostname === '[::1]'

/**
 * Registration is the one endpoint that lets a stranger write to the client store, so the metadata
 * it accepts is checked as strictly as anything a human would have registered (NFR-S2).
 */
const validateRedirectUris = (uris: unknown) => {
  if (!Array.isArray(uris) || uris.length === 0)
    throw invalid('redirect_uris is required and must be a non-empty array', 'invalid_redirect_uri')
  for (const raw of uris) {
    if (typeof raw !== 'string') throw invalid('every redirect_uri must be a string', 'invalid_redirect_uri')
    let url: URL
    try {
      url = new URL(raw)
    } catch {
      throw invalid(`redirect_uri ${raw} is not an absolute URL`, 'invalid_redirect_uri')
    }
    // A fragment can never be matched: the browser never sends it (RFC 6749 §3.1.2).
    if (url.hash) throw invalid(`redirect_uri ${raw} must not carry a fragment`, 'invalid_redirect_uri')
    if (url.protocol === 'http:' && !isLoopback(url)) {
      throw invalid(`redirect_uri ${raw} must be https outside loopback`, 'invalid_redirect_uri')
    }
  }
  return uris as string[]
}

const metadataFrom = (config: ResolvedConfig, body: Record<string, unknown>): Client => {
  const redirectUris = validateRedirectUris(body.redirect_uris)
  const method = (body.token_endpoint_auth_method as ClientAuthMethod | undefined) ?? 'client_secret_basic'
  if (!config.clientAuthMethods.includes(method)) throw invalid(`token_endpoint_auth_method ${method} is not offered by this provider`)

  const grantTypes = (body.grant_types as string[] | undefined) ?? DEFAULT_GRANTS
  const responseTypes = (body.response_types as string[] | undefined) ?? DEFAULT_RESPONSE_TYPES
  if (responseTypes.some(type => type.split(' ').includes('token')))
    throw invalid('this provider issues no tokens from the authorization endpoint')

  const scopes = ((body.scope as string | undefined) ?? 'openid').split(' ').filter(Boolean)
  const unknown = scopes.filter(scope => !config.scopes.includes(scope))
  if (unknown.length) throw invalid(`unknown scope: ${unknown.join(', ')}`)

  const now = new Date()
  return {
    clientId: token(16),
    ...(method !== 'none' && { clientSecret: token() }),
    ...(typeof body.client_name === 'string' && { clientName: body.client_name }),
    redirectUris,
    ...(Array.isArray(body.post_logout_redirect_uris) && { postLogoutRedirectUris: body.post_logout_redirect_uris as string[] }),
    grantTypes,
    responseTypes,
    scopes,
    tokenEndpointAuthMethod: method,
    ...(body.jwks ? { jwks: body.jwks as { keys: unknown[] } } : {}),
    ...(typeof body.jwks_uri === 'string' && { jwksUri: body.jwks_uri }),
    ...(typeof body.backchannel_logout_uri === 'string' && { backchannelLogoutUri: body.backchannel_logout_uri }),
    // FR-C3: not negotiable, whoever registered it.
    requirePkce: true,
    registrationAccessToken: token(),
    createdAt: now,
    updatedAt: now
  }
}

export const clientResponse = (config: ResolvedConfig, client: Client) => ({
  client_id: client.clientId,
  ...(client.clientSecret && { client_secret: client.clientSecret }),
  ...(client.clientName && { client_name: client.clientName }),
  redirect_uris: client.redirectUris,
  grant_types: client.grantTypes,
  response_types: client.responseTypes,
  scope: client.scopes.join(' '),
  token_endpoint_auth_method: client.tokenEndpointAuthMethod,
  client_id_issued_at: Math.floor(client.createdAt.getTime() / 1000),
  ...(client.registrationAccessToken && {
    registration_access_token: client.registrationAccessToken,
    registration_client_uri: `${config.issuer}${config.routes.registration}?client_id=${encodeURIComponent(client.clientId)}`
  })
})

const authorizeRegistrationAccess = async (config: ResolvedConfig, request: Request, clientId: string | null) => {
  if (!clientId) throw new OAuthError('invalid_request', { description: 'client_id is required', status: 400 })
  const header = request.headers.get('authorization')
  const presented = header?.toLowerCase().startsWith('bearer ') ? header.slice(7).trim() : undefined
  const client = await config.adapter.clients.find(clientId)
  // An unknown client and a wrong token are the same answer: otherwise this enumerates client ids.
  if (!client || !presented || !client.registrationAccessToken || presented !== client.registrationAccessToken) {
    throw new OAuthError('invalid_client', {
      description: 'no registration access token for this client',
      spec: 'RFC 7592 §2',
      status: 401,
      headers: { 'www-authenticate': 'Bearer' }
    })
  }
  return client
}

/** OIDC Dynamic Client Registration 1.0 and RFC 7592. Off unless a deployment turns it on (FR-C9). */
export const registrationEndpoint = async (config: ResolvedConfig, request: Request) => {
  const url = new URL(request.url)

  if (request.method === 'POST') {
    if (config.onRegister) await config.onRegister(request)
    const body = (await request.json().catch(() => {
      throw invalid('the registration request must be JSON')
    })) as Record<string, unknown>

    const client = metadataFrom(config, body)
    if (!config.adapter.clients.create) throw new OAuthError('server_error', { description: 'this adapter cannot create clients' })
    await config.adapter.clients.create(client)
    await config.onAudit?.({ action: 'client.register', clientId: client.clientId, at: new Date() })
    return Response.json(clientResponse(config, client), { status: 201, headers: { 'cache-control': 'no-store' } })
  }

  const client = await authorizeRegistrationAccess(config, request, url.searchParams.get('client_id'))

  if (request.method === 'GET') {
    return Response.json(clientResponse(config, client), { headers: { 'cache-control': 'no-store' } })
  }

  if (request.method === 'DELETE') {
    await config.adapter.clients.destroy?.(client.clientId)
    await config.onAudit?.({ action: 'client.delete', clientId: client.clientId, at: new Date() })
    return new Response(null, { status: 204, headers: { 'cache-control': 'no-store' } })
  }

  const body = (await request.json().catch(() => {
    throw invalid('the update must be JSON')
  })) as Record<string, unknown>
  const replacement = metadataFrom(config, body)
  // Identity and the token that grants access to it are the server's, not the client's to change.
  const updated: Client = {
    ...replacement,
    clientId: client.clientId,
    ...(client.clientSecret && { clientSecret: client.clientSecret }),
    registrationAccessToken: client.registrationAccessToken as string,
    createdAt: client.createdAt,
    updatedAt: new Date()
  }
  await config.adapter.clients.update?.(client.clientId, updated)
  await config.onAudit?.({ action: 'client.update', clientId: client.clientId, at: new Date() })
  return Response.json(clientResponse(config, updated), { headers: { 'cache-control': 'no-store' } })
}
