import type { Adapter } from '../adapter'
import type { ResolvedConfig } from '../config'
import { OAuthError } from '../errors'
import type { Client, ClientAuthMethod } from '../types'
import { browserUri, serverUri } from './registration'

const SPEC = 'draft-ietf-oauth-client-id-metadata-document §4.1'

const refuse = (description: string) => new OAuthError('invalid_client', { description, spec: SPEC, status: 400 })

/**
 * §3: https, a path, and nothing that hides what it names. Requiring the URL's canonical form also
 * rules out dot segments, which a parser would otherwise resolve away unseen.
 */
const assertClientIdUrl = (clientId: string) => {
  const url = URL.canParse(clientId) ? new URL(clientId) : undefined
  if (!url || url.href !== clientId) throw refuse(`client_id ${clientId} is not a URL in canonical form`)
  if (url.pathname === '/') throw refuse(`client_id ${clientId} must name a path`)
  if (url.username || url.password || url.search || url.hash) {
    throw refuse(`client_id ${clientId} must not carry credentials, a query or a fragment`)
  }
  // Fetched on a stranger's say-so: an address or localhost aims the request inside the network.
  serverUri(clientId, 'client_id')
}

const ALLOWED_METHODS: ClientAuthMethod[] = ['none', 'private_key_jwt']
const ALLOWED_GRANTS = ['authorization_code', 'refresh_token']

/** The client a metadata document describes, or a refusal saying why it cannot be one. */
const clientFrom = (config: ResolvedConfig, clientId: string, document: unknown): Client => {
  if (!document || typeof document !== 'object' || Array.isArray(document)) throw refuse(`the document at ${clientId} is not a JSON object`)
  const body = document as Record<string, unknown>
  if (body.client_id !== clientId) throw refuse(`the document at ${clientId} names a different client_id`)
  if ('client_secret' in body || 'client_secret_expires_at' in body) throw refuse('a metadata document cannot hold a shared secret')

  const method = (body.token_endpoint_auth_method ?? 'none') as ClientAuthMethod
  if (!ALLOWED_METHODS.includes(method))
    throw refuse(`token_endpoint_auth_method ${method} needs a shared secret, which a public document cannot hold`)
  if (!config.clientAuthMethods.includes(method)) throw refuse(`token_endpoint_auth_method ${method} is not offered by this provider`)
  if (method === 'private_key_jwt' && !body.jwks && !body.jwks_uri) throw refuse('private_key_jwt needs jwks or jwks_uri')

  if (body.application_type !== undefined && body.application_type !== 'web' && body.application_type !== 'native') {
    throw refuse(`application_type ${String(body.application_type)} is neither web nor native`)
  }
  // MCP's own example document registers localhost callbacks without naming itself native.
  const applicationType = body.application_type === 'web' ? 'web' : 'native'
  if (!Array.isArray(body.redirect_uris) || body.redirect_uris.length === 0) throw refuse('redirect_uris is required')
  const redirectUris = body.redirect_uris.map(uri => browserUri(uri, 'redirect_uri', 'invalid_redirect_uri', applicationType === 'native'))

  const grantTypes = (body.grant_types as string[] | undefined) ?? ['authorization_code']
  const unsupported = grantTypes.filter(grant => !ALLOWED_GRANTS.includes(grant))
  if (unsupported.length) throw refuse(`grant_types ${unsupported.join(', ')} are not available to a metadata-document client`)

  const scopes = typeof body.scope === 'string' ? body.scope.split(' ').filter(Boolean) : config.scopes
  const unknown = scopes.filter(scope => !config.scopes.includes(scope))
  if (unknown.length) throw refuse(`unknown scope: ${unknown.join(', ')}`)

  const now = new Date()
  return {
    clientId,
    ...(typeof body.client_name === 'string' && { clientName: body.client_name }),
    applicationType,
    redirectUris,
    grantTypes,
    responseTypes: ['code'],
    scopes,
    tokenEndpointAuthMethod: method,
    ...(body.jwks ? { jwks: body.jwks as { keys: unknown[] } } : {}),
    ...(body.jwks_uri !== undefined && { jwksUri: serverUri(body.jwks_uri, 'jwks_uri') }),
    // FR-C3: a document vouches for nothing, so PKCE is never optional for one.
    requirePkce: true,
    createdAt: now,
    updatedAt: now
  }
}

/**
 * Client ID Metadata Documents (FR-C20): an `https` client_id the store does not hold is resolved
 * through the host's `resolveClientMetadata`, which does the fetching, caching and trust policy the
 * core cannot (FR-A1). Everything the document says is checked here, so every grant sees an
 * ordinary client.
 */
export const withClientMetadata = (config: ResolvedConfig, resolve: (clientId: string) => Promise<unknown>): Adapter => ({
  ...config.adapter,
  clients: {
    ...config.adapter.clients,
    async find(clientId) {
      const stored = await config.adapter.clients.find(clientId)
      if (stored || !clientId.startsWith('https://')) return stored
      assertClientIdUrl(clientId)
      const document = await resolve(clientId)
      return document === undefined ? undefined : clientFrom(config, clientId, document)
    }
  }
})
