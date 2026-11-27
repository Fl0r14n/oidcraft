/// <reference types="bun" />
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { WebStandardStreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js'
import { type Provider, protectedResourceMetadata, protectedResourceMetadataUrl, type ResourceDescriptor } from '@oidcraft/provider'
import { safeFetch } from '@oidcraft/provider/runtimes/bun'
import { issuer, optional } from '../op/env'

/** Off unless OIDCRAFT_MCP=on, since an MCP resource (FR-C19) also opens client registration (FR-C9, FR-C20). */
export const mcpEnabled = optional('OIDCRAFT_MCP') === 'on'

export const MCP_PATH = '/mcp'
const mcpUri = () => `${issuer()}${MCP_PATH}`

export const mcpResources = (): ResourceDescriptor[] => (mcpEnabled ? [{ uri: mcpUri(), scopes: ['openid', 'profile'] }] : [])

/**
 * Fetched as FR-C20 leaves to the host, through safeFetch (D-6): a client_id is any URL its client chose, so no address
 * inside this network, no redirect, a short deadline and a small body; the core already refused a non-canonical URL.
 */
export const resolveClientMetadata = async (clientId: string) => {
  const response = await safeFetch(clientId, { maxBytes: 5_120, timeoutMs: 5_000 }).catch(() => undefined)
  return response?.ok ? ((await response.json().catch(() => undefined)) as unknown) : undefined
}

const metadataUrl = () => protectedResourceMetadataUrl(mcpUri())

export const mcpRoutes = async (provider: Provider, request: Request, url: URL) => {
  if (url.pathname === new URL(metadataUrl()).pathname) return Response.json(protectedResourceMetadata(provider.config, mcpUri()))
  if (url.pathname !== MCP_PATH) return undefined

  // D-8: a token for this resource alone, its DPoP proof or certificate included; a refusal's 401 names the metadata, which
  // names this OP, as MCP 2025-06-18 §2.3.1 asks.
  const verified = await provider.verifyAccessToken(request, { resource: mcpUri(), url: `${mcpUri()}${url.search}` })
  if (!verified.ok) {
    console.log(`[mcp] refused a token: ${verified.reason}`)
    return verified.response
  }
  const { token } = verified
  const authInfo = {
    token: request.headers.get('authorization')?.replace(/^\S+\s+/, '') ?? '',
    clientId: token.clientId,
    scopes: token.scopes,
    extra: { sub: token.subject }
  }
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
