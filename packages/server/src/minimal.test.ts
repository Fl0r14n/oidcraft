import { describe, expect, test } from 'bun:test'
import { memoryAdapter } from './adapters/memory'
import { createProvider } from './provider'

/**
 * NFR-D1 promises "a working OP, in memory, in under 30 lines and with no database". A promise with
 * a number in it is worth counting rather than asserting, so this counts it.
 */
const EXAMPLE = `import { createProvider } from 'oidcraft'
import { memoryAdapter } from 'oidcraft/adapters/memory'

const adapter = await memoryAdapter({
  accounts: {
    find: async accountId => ({ accountId, claims: {} }),
    claims: async accountId => ({ name: accountId })
  }
})

await adapter.clients.create?.({
  clientId: 'demo',
  redirectUris: ['http://localhost:3000/callback'],
  grantTypes: ['authorization_code', 'refresh_token'],
  responseTypes: ['code'],
  scopes: ['openid', 'profile'],
  tokenEndpointAuthMethod: 'none',
  createdAt: new Date(),
  updatedAt: new Date()
})

const provider = createProvider({
  issuer: 'http://localhost:3001',
  adapter,
  interactionUrl: 'http://localhost:3001/interaction'
})

Bun.serve({ port: 3001, fetch: request => provider.handle(request) })`

describe('the smallest usable provider', () => {
  test('fits in under 30 lines, as NFR-D1 says', () => {
    const lines = EXAMPLE.split('\n').filter(line => line.trim()).length
    expect({ lines, under30: lines < 30 }).toEqual({ lines, under30: true })
  })

  // Counting lines proves nothing if they do not run, so the same code runs here.
  test('actually serves a provider', async () => {
    const adapter = await memoryAdapter({
      accounts: {
        find: async accountId => ({ accountId, claims: {} }),
        claims: async accountId => ({ name: accountId })
      }
    })

    await adapter.clients.create?.({
      clientId: 'demo',
      redirectUris: ['http://localhost:3000/callback'],
      grantTypes: ['authorization_code', 'refresh_token'],
      responseTypes: ['code'],
      scopes: ['openid', 'profile'],
      tokenEndpointAuthMethod: 'none',
      createdAt: new Date(),
      updatedAt: new Date()
    })

    const provider = createProvider({
      issuer: 'http://localhost:3001',
      adapter,
      interactionUrl: 'http://localhost:3001/interaction'
    })

    const discovery = await provider.handle(new Request('http://localhost:3001/.well-known/openid-configuration'))
    expect(discovery.status).toBe(200)
    expect((await discovery.json()).issuer).toBe('http://localhost:3001')

    const jwks = await provider.handle(new Request('http://localhost:3001/jwks'))
    expect((await jwks.json()).keys).toHaveLength(1)

    // And it can actually start an authorization, which is the part that makes it a provider.
    const authorize = await provider.handle(
      new Request(
        `http://localhost:3001/authorize?${new URLSearchParams({
          client_id: 'demo',
          redirect_uri: 'http://localhost:3000/callback',
          response_type: 'code',
          scope: 'openid profile',
          code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
          code_challenge_method: 'S256'
        })}`
      )
    )
    expect(authorize.status).toBe(303)
    expect(authorize.headers.get('location')).toContain('/interaction/')
  })

  // NFR-D2: an unusable combination fails here rather than at the first request.
  test('a misconfiguration fails at construction, not at the first request', async () => {
    const adapter = await memoryAdapter()
    expect(() => createProvider({ issuer: 'not-a-url', adapter })).toThrow(/not an absolute URL/)
  })
})
