import { beforeEach, describe, expect, test } from 'bun:test'
import { memoryAdapter } from '@oidcraft/adapter/memory'
import type { Adapter, Client } from '../index'
import { createProvider, type Provider } from '../provider'
import { basic, ISSUER, SECRET_HASH } from '../test-flow'
import { protectedResourceMetadataUrl } from './protected-resource'

const MCP = 'https://mcp.example.com/mcp'
const API = 'https://api.example.com'

const client: Client = {
  clientId: 'rp',
  clientSecretHash: SECRET_HASH,
  redirectUris: [],
  grantTypes: ['client_credentials'],
  responseTypes: [],
  scopes: ['tools'],
  tokenEndpointAuthMethod: 'client_secret_basic',
  createdAt: new Date(),
  updatedAt: new Date()
}

let adapter: Adapter
let provider: Provider

beforeEach(async () => {
  adapter = await memoryAdapter({ accounts: { find: async () => undefined, claims: async () => ({}) } })
  await adapter.clients.upsert?.(client)
  provider = createProvider({
    issuer: ISSUER,
    adapter,
    interactionUrl: `${ISSUER}/interaction`,
    scopes: ['openid', 'tools'],
    resources: [{ uri: MCP }, { uri: API }],
    features: { revocation: true }
  })
})

const tokenFor = async (resource?: string) => {
  const response = await provider.handle(
    new Request(`${ISSUER}/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: basic() },
      body: new URLSearchParams({ grant_type: 'client_credentials', scope: 'tools', ...(resource && { resource }) })
    })
  )
  return ((await response.json()) as { access_token: string }).access_token
}

const at = (token?: string) => new Request(`${MCP}?q=1`, { headers: token ? { authorization: `Bearer ${token}` } : {} })

describe('verifyAccessToken', () => {
  test('a token for the resource passes, with what the resource server needs of it', async () => {
    const verified = await provider.verifyAccessToken(at(await tokenFor(MCP)), { resource: MCP })
    if (!verified.ok) throw new Error(verified.description)
    expect(verified.token).toMatchObject({ clientId: 'rp', scopes: ['tools'], accountId: undefined, subject: undefined })
    expect(verified.token.expiresAt.getTime()).toBeGreaterThan(Date.now())
  })

  // FR-C19: a token issued for one MCP server is useless at another.
  test("a token for another resource is refused with the resource's metadata in the challenge", async () => {
    const verified = await provider.verifyAccessToken(at(await tokenFor(API)), { resource: MCP })
    if (verified.ok) throw new Error('verified')
    expect(verified.reason).toBe('invalid_token')
    expect(verified.response.status).toBe(401)
    expect(verified.response.headers.get('www-authenticate')).toBe(
      `Bearer error="invalid_token", error_description="this access token was not issued for this resource", resource_metadata="${protectedResourceMetadataUrl(MCP)}"`
    )
    expect((await verified.response.json()).error).toBe('invalid_token')
  })

  // FR-C5: without a resource, only a token for none passes, as at UserInfo.
  test('without a resource, a token for one is refused and a token for none passes', async () => {
    expect((await provider.verifyAccessToken(at(await tokenFor(MCP)))).ok).toBe(false)
    expect((await provider.verifyAccessToken(at(await tokenFor()))).ok).toBe(true)
    expect((await provider.verifyAccessToken(at(await tokenFor()), { resource: MCP })).ok).toBe(false)
  })

  test('no token is refused with a challenge', async () => {
    const verified = await provider.verifyAccessToken(at(), { resource: MCP })
    if (verified.ok) throw new Error('verified')
    expect(verified.reason).toBe('invalid_request')
    expect(verified.response.status).toBe(401)
    expect(verified.response.headers.get('www-authenticate')).toContain(`resource_metadata="${protectedResourceMetadataUrl(MCP)}"`)
  })

  test('a revoked token is refused', async () => {
    const token = await tokenFor(MCP)
    await provider.handle(
      new Request(`${ISSUER}/revoke`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: basic() },
        body: new URLSearchParams({ token })
      })
    )
    const verified = await provider.verifyAccessToken(at(token), { resource: MCP })
    expect(verified.ok ? undefined : verified.reason).toBe('invalid_token')
  })
})
