/// <reference types="bun" />
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { WebStandardStreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js'
import { type Adapter, type Provider, protectedResourceMetadata, protectedResourceMetadataUrl, type ResourceDescriptor } from 'oidcraft'
import { issuer, optional } from '../op/env'

/**
 * An MCP server on this OP, as an MCP client meets one: a protected resource whose tokens this OP
 * issues for it alone (FR-C19, MCP 2026-07-28). Off unless OIDCRAFT_MCP=on, since it also opens
 * client registration — an MCP client registers itself or names a metadata document (FR-C9, FR-C20).
 */
export const mcpEnabled = optional('OIDCRAFT_MCP') === 'on'

export const MCP_PATH = '/mcp'
const MCP_RESOURCE_SERVER = 'oidcraft-mcp'
const mcpUri = () => `${issuer()}${MCP_PATH}`

/** Only this process introspects with it, so it is minted per boot and never written down. */
const secret = crypto.randomUUID()

export const mcpResources = (): ResourceDescriptor[] =>
  mcpEnabled ? [{ uri: mcpUri(), resourceServer: MCP_RESOURCE_SERVER, scopes: ['openid', 'profile'] }] : []

export const seedMcpResourceServer = async (adapter: Adapter) => {
  if (!mcpEnabled) return
  const now = new Date()
  await adapter.clients.upsert?.({
    clientId: MCP_RESOURCE_SERVER,
    clientSecret: secret,
    clientName: 'oidcraft MCP server',
    redirectUris: [],
    grantTypes: [],
    responseTypes: [],
    scopes: [],
    tokenEndpointAuthMethod: 'client_secret_basic',
    createdAt: now,
    updatedAt: now
  })
  console.log(`[oidcraft] MCP server at ${mcpUri()}`)
}

/**
 * The client's metadata document, fetched as FR-C20 leaves to the host: a short timeout, no redirects
 * and a small body. The core has already refused anything but a canonical https URL.
 */
export const resolveClientMetadata = async (clientId: string) => {
  const response = await fetch(clientId, { redirect: 'error', signal: AbortSignal.timeout(5000) }).catch(() => undefined)
  if (!response?.ok) return undefined
  const body = await response.text()
  if (body.length > 5_000) return undefined
  return JSON.parse(body) as unknown
}

const metadataUrl = () => protectedResourceMetadataUrl(mcpUri())

/** Introspected in this process, as the MCP server's own client: a token for any other audience is refused. */
const callerOf = async (provider: Provider, request: Request) => {
  const header = request.headers.get('authorization')
  if (!header?.toLowerCase().startsWith('bearer ')) return undefined
  const token = header.slice(7).trim()
  const response = await provider.handle(
    new Request(`${provider.config.issuer}${provider.config.routes.introspection}`, {
      method: 'POST',
      headers: {
        authorization: `Basic ${btoa(`${MCP_RESOURCE_SERVER}:${secret}`)}`,
        'content-type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({ token })
    })
  )
  const body = (await response.json()) as { active?: boolean; aud?: string; sub?: string; client_id?: string; scope?: string }
  if (!body.active || body.aud !== mcpUri()) {
    console.log(`[mcp] refused a token: active=${body.active} aud=${body.aud}`)
    return undefined
  }
  return { token, clientId: body.client_id ?? '', scopes: body.scope?.split(' ') ?? [], extra: { sub: body.sub } }
}

/** MCP 2025-06-18 §2.3.1: the 401 names the metadata, which names this OP. */
const unauthorized = () =>
  new Response(null, { status: 401, headers: { 'www-authenticate': `Bearer resource_metadata="${metadataUrl()}"` } })

export const mcpRoutes = async (provider: Provider, request: Request, url: URL) => {
  if (url.pathname === new URL(metadataUrl()).pathname) return Response.json(protectedResourceMetadata(provider.config, mcpUri()))
  if (url.pathname !== MCP_PATH) return undefined

  const authInfo = await callerOf(provider, request)
  if (!authInfo) return unauthorized()
  console.log(`[mcp] ${request.method} from ${authInfo.clientId} as ${authInfo.extra.sub}`)

  // Stateless: a server and a transport per request, so nothing outlives the token that authorised it.
  const server = new McpServer({ name: 'oidcraft-demo', version: '1.0.0' })
  server.registerTool('whoami', { description: 'Who this MCP server sees: the signed-in account and the client acting for it' }, () => ({
    content: [{ type: 'text', text: JSON.stringify({ subject: authInfo.extra.sub, client: authInfo.clientId, scopes: authInfo.scopes }) }]
  }))
  const transport = new WebStandardStreamableHTTPServerTransport({ enableJsonResponse: true })
  await server.connect(transport)
  return transport.handleRequest(request, { authInfo })
}
