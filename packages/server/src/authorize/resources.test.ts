import { beforeEach, describe, expect, test } from 'bun:test'
import { randomString, sha256 } from '@oidcraft/core'
import { base64url, decodeJwt } from 'jose'
import { memoryAdapter } from '../adapters/memory'
import { resolveConfig } from '../config'
import { ConfigurationError } from '../errors'
import type { Adapter, Client } from '../index'
import { createProvider, type Provider } from '../provider'
import { protectedResourceMetadata, protectedResourceMetadataUrl } from '../resource/protected-resource'
import { SESSION_COOKIE } from '../session/session'

const ISSUER = 'https://op.example.com'
const REDIRECT = 'https://rp.example.com/cb'
const MCP = 'https://mcp.example.com/mcp'
const API = 'https://api.example.com'
const SECRET = 'shhh-a-long-enough-secret'

const client = (over: Partial<Client> = {}): Client => ({
  clientId: 'rp',
  clientSecret: SECRET,
  redirectUris: [REDIRECT],
  grantTypes: ['authorization_code', 'refresh_token', 'client_credentials'],
  responseTypes: ['code'],
  scopes: ['openid', 'profile', 'offline_access', 'tools'],
  tokenEndpointAuthMethod: 'client_secret_basic',
  createdAt: new Date(),
  updatedAt: new Date(),
  ...over
})

const accounts = {
  async find(accountId: string) {
    return { accountId, claims: {} }
  },
  async claims() {
    return {}
  }
}

let adapter: Adapter
let provider: Provider
let verifier: string
let challenge: string

beforeEach(async () => {
  adapter = await memoryAdapter({ accounts })
  await adapter.clients.upsert?.(client())
  await adapter.clients.upsert?.(client({ clientId: 'jwt-rp', accessTokenFormat: 'jwt' }))
  // The MCP server introspects as its own resource-server client; the API is another one.
  await adapter.clients.upsert?.(client({ clientId: 'mcp-server', resourceServer: true, redirectUris: [], grantTypes: [] }))
  await adapter.clients.upsert?.(client({ clientId: 'api-server', resourceServer: true, redirectUris: [], grantTypes: [] }))
  provider = createProvider({
    issuer: ISSUER,
    adapter,
    interactionUrl: `${ISSUER}/interaction`,
    scopes: ['openid', 'profile', 'offline_access', 'tools'],
    resources: [
      { uri: MCP, resourceServer: 'mcp-server' },
      { uri: API, resourceServer: 'api-server' }
    ]
  })
  verifier = randomString() + randomString()
  challenge = base64url.encode(await sha256(verifier))
})

const basic = (id = 'rp') => `Basic ${btoa(`${id}:${SECRET}`)}`

const post = (path: string, body: Record<string, string | string[]>, id = 'rp') => {
  const form = new URLSearchParams()
  for (const [key, value] of Object.entries(body)) for (const each of [value].flat()) form.append(key, each)
  return provider.handle(
    new Request(`${ISSUER}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: basic(id) },
      body: form.toString()
    })
  )
}

const authorize = (resources: string[], clientId = 'rp') => {
  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: REDIRECT,
    response_type: 'code',
    scope: 'openid offline_access tools',
    state: 's',
    nonce: 'n',
    code_challenge: challenge,
    code_challenge_method: 'S256'
  })
  for (const resource of resources) params.append('resource', resource)
  return provider.handle(new Request(`${ISSUER}/authorize?${params}`))
}

/** Through login and consent to a code, the way a browser would. */
const codeFor = async (resources: string[], clientId = 'rp') => {
  const first = await authorize(resources, clientId)
  const loginId = new URL(first.headers.get('location') as string).pathname.split('/').pop() as string
  const login = await provider.interactions.complete(loginId, { login: { accountId: 'ada' } })
  const cookie = `${SESSION_COOKIE}=${(login.setCookie as string).split('=')[1]?.split(';')[0]}`
  const second = await provider.handle(new Request(login.redirectTo, { headers: { cookie } }))
  const consentId = new URL(second.headers.get('location') as string).pathname.split('/').pop() as string
  const consent = await provider.interactions.complete(consentId, { consent: { scopes: ['openid', 'offline_access', 'tools'] } })
  const third = await provider.handle(new Request(consent.redirectTo, { headers: { cookie } }))
  return new URL(third.headers.get('location') as string).searchParams.get('code') as string
}

const redeem = (code: string, resource?: string | string[], clientId = 'rp') =>
  post(
    '/token',
    { grant_type: 'authorization_code', code, redirect_uri: REDIRECT, code_verifier: verifier, ...(resource && { resource }) },
    clientId
  )

const introspect = async (token: string, as: string) => (await post('/introspect', { token }, as)).json()

describe('resource indicators (RFC 8707, FR-C19)', () => {
  test('a token for a resource carries it as its audience, and only that resource server sees it', async () => {
    const tokens = await (await redeem(await codeFor([MCP]), MCP)).json()
    expect((await introspect(tokens.access_token, 'mcp-server')).aud).toBe(MCP)
    expect(await introspect(tokens.access_token, 'api-server')).toEqual({ active: false })
  })

  test('the resource named at authorization is the audience when the token request repeats none', async () => {
    const tokens = await (await redeem(await codeFor([MCP]))).json()
    expect((await introspect(tokens.access_token, 'rp')).aud).toBe(MCP)
  })

  test('a resource nobody configured is refused at authorization, back to the client', async () => {
    const response = await authorize(['https://evil.example.net/mcp'])
    const location = new URL(response.headers.get('location') as string)
    expect(location.origin + location.pathname).toBe(REDIRECT)
    expect(location.searchParams.get('error')).toBe('invalid_target')
  })

  test('a resource with a fragment is refused', async () => {
    const response = await authorize([`${MCP}#x`])
    expect(new URL(response.headers.get('location') as string).searchParams.get('error')).toBe('invalid_target')
  })

  // A refused token request must not burn the code: the client can retry with the right resource.
  test('a token request may not name a resource the authorization did not, and the code survives it', async () => {
    const code = await codeFor([MCP])
    const refused = await redeem(code, API)
    expect(refused.status).toBe(400)
    expect((await refused.json()).error).toBe('invalid_target')
    expect((await redeem(code, MCP)).status).toBe(200)
  })

  test('naming a resource only at the token request narrows the token to it', async () => {
    const tokens = await (await redeem(await codeFor([]), API)).json()
    expect((await introspect(tokens.access_token, 'api-server')).aud).toBe(API)
    expect(await introspect(tokens.access_token, 'mcp-server')).toEqual({ active: false })
  })

  test('several resources at authorization: the token request picks one, and must', async () => {
    const code = await codeFor([MCP, API])
    expect((await (await redeem(code)).json()).error).toBe('invalid_target')
    expect((await redeem(code, [MCP, API])).status).toBe(400)
    const tokens = await (await redeem(code, API)).json()
    expect((await introspect(tokens.access_token, 'api-server')).aud).toBe(API)
  })

  test('a refresh keeps to the resources the authorization covered', async () => {
    const tokens = await (await redeem(await codeFor([MCP]), MCP)).json()
    const refused = await post('/token', { grant_type: 'refresh_token', refresh_token: tokens.refresh_token, resource: API })
    expect((await refused.json()).error).toBe('invalid_target')
    const refreshed = await (await post('/token', { grant_type: 'refresh_token', refresh_token: tokens.refresh_token })).json()
    expect((await introspect(refreshed.access_token, 'mcp-server')).aud).toBe(MCP)
  })

  test('client credentials can name a resource', async () => {
    const tokens = await (await post('/token', { grant_type: 'client_credentials', scope: 'tools', resource: MCP })).json()
    expect((await introspect(tokens.access_token, 'mcp-server')).aud).toBe(MCP)
  })

  test('a JWT access token is addressed to the resource', async () => {
    const tokens = await (await redeem(await codeFor([MCP], 'jwt-rp'), MCP, 'jwt-rp')).json()
    expect(decodeJwt(tokens.access_token).aud).toBe(MCP)
  })

  test('without resource indicators nothing changes', async () => {
    const tokens = await (await redeem(await codeFor([]))).json()
    expect((await introspect(tokens.access_token, 'rp')).aud).toBe('rp')
    expect((await introspect(tokens.access_token, 'mcp-server')).active).toBe(true)
  })
})

describe('configured resources', () => {
  const problems = (uri: string) => {
    try {
      resolveConfig({ issuer: ISSUER, adapter, interactionUrl: `${ISSUER}/interaction`, resources: [{ uri }] })
      return ''
    } catch (error) {
      return error instanceof ConfigurationError ? error.message : String(error)
    }
  }

  test('must be absolute, without a fragment, and https outside loopback', () => {
    expect(problems('mcp.example.com')).toContain('absolute URI')
    expect(problems(`${MCP}#frag`)).toContain('without a fragment')
    expect(problems('http://mcp.example.com/mcp')).toContain('https')
    expect(problems('http://localhost:8080/mcp')).toBe('')
  })

  test('may not be listed twice', () => {
    expect(() =>
      resolveConfig({ issuer: ISSUER, adapter, interactionUrl: `${ISSUER}/interaction`, resources: [{ uri: MCP }, { uri: MCP }] })
    ).toThrow(/listed twice/)
  })
})

describe('protected-resource metadata (RFC 9728)', () => {
  test('names this provider as the issuer of the resource', () => {
    expect(protectedResourceMetadata(provider.config, MCP)).toEqual({
      resource: MCP,
      authorization_servers: [ISSUER],
      bearer_methods_supported: ['header']
    })
    expect(() => protectedResourceMetadata(provider.config, 'https://unknown.example.com')).toThrow(/not one of/)
  })

  test('is served under the well-known segment inserted before the path', () => {
    expect(protectedResourceMetadataUrl(MCP)).toBe('https://mcp.example.com/.well-known/oauth-protected-resource/mcp')
    expect(protectedResourceMetadataUrl(API)).toBe('https://api.example.com/.well-known/oauth-protected-resource')
  })
})
