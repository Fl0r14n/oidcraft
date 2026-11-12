import type { Adapter, Client, ClientAuthMethod } from '@oidcraft/adapter'
import type { ResolvedConfig } from '../config'
import { OAuthError } from '../errors'
import { browserUri, keysFrom, objectFrom, serverUri, stringFrom, stringsFrom } from './registration'

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
  serverUri(clientId, 'client_id', refuse)
}

const ALLOWED_METHODS: ClientAuthMethod[] = ['none', 'private_key_jwt']
const ALLOWED_GRANTS = ['authorization_code', 'refresh_token']

/** The client a metadata document describes, or a refusal saying why it cannot be one. */
const clientFrom = (config: ResolvedConfig, clientId: string, document: unknown): Client => {
  const body = objectFrom(document, `the document at ${clientId}`, refuse)
  if (body.client_id !== clientId) throw refuse(`the document at ${clientId} names a different client_id`)
  if ('client_secret' in body || 'client_secret_expires_at' in body) throw refuse('a metadata document cannot hold a shared secret')

  const method = (stringFrom(body.token_endpoint_auth_method, 'token_endpoint_auth_method', refuse) ?? 'none') as ClientAuthMethod
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
  const redirectUris = body.redirect_uris.map(uri =>
    browserUri(uri, 'redirect_uri', { native: applicationType === 'native', fail: refuse })
  )

  const grantTypes = stringsFrom(body.grant_types, 'grant_types', refuse) ?? ['authorization_code']
  const unsupported = grantTypes.filter(grant => !ALLOWED_GRANTS.includes(grant))
  if (unsupported.length) throw refuse(`grant_types ${unsupported.join(', ')} are not available to a metadata-document client`)

  const scopes = stringFrom(body.scope, 'scope', refuse)?.split(' ').filter(Boolean) ?? config.scopes
  const unknown = scopes.filter(scope => !config.scopes.includes(scope))
  if (unknown.length) throw refuse(`unknown scope: ${unknown.join(', ')}`)

  const clientName = stringFrom(body.client_name, 'client_name', refuse)
  const now = new Date()
  return {
    clientId,
    ...(clientName !== undefined && { clientName }),
    applicationType,
    redirectUris,
    grantTypes,
    responseTypes: ['code'],
    scopes,
    tokenEndpointAuthMethod: method,
    ...keysFrom(body, refuse),
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
