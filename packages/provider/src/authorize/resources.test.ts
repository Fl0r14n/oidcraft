import { beforeEach, describe, expect, test } from 'bun:test'
import { ConfigurationError } from '@oidcraft/adapter'
import { memoryAdapter } from '@oidcraft/adapter/memory'
import { randomString, sha256 } from '@oidcraft/core'
import { base64url, decodeJwt } from 'jose'
import { resolveConfig } from '../config'
import type { Adapter, Client } from '../index'
import { createProvider, type Provider } from '../provider'
import { protectedResourceMetadata, protectedResourceMetadataUrl } from '../resource/protected-resource'
import { SESSION_COOKIE } from '../session/session'
import { basic, browserOf, ISSUER, REDIRECT, SECRET_HASH } from '../test-flow'

const MCP = 'https://mcp.example.com/mcp'
const API = 'https://api.example.com'

const client = (over: Partial<Client> = {}): Client => ({
  clientId: 'rp',
  clientSecretHash: SECRET_HASH,
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
    return { name: 'Ada' }
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
  const login = await provider.interactions.complete(loginId, { login: { accountId: 'ada' } }, browserOf(first))
  const cookie = `__Host-${SESSION_COOKIE}=${(login.setCookie as string).split('=')[1]?.split(';')[0]}`
  const second = await provider.handle(new Request(login.redirectTo, { headers: { cookie } }))
  const consentId = new URL(second.headers.get('location') as string).pathname.split('/').pop() as string
  const consent = await provider.interactions.complete(
    consentId,
    { consent: { scopes: ['openid', 'offline_access', 'tools'] } },
    browserOf(second)
  )
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

  // Naming a client as a resource's server is the whole grant: it needs no FR-C8 flag, and so gets
  // no view of tokens that were never for its resource.
  test("a resource server named only by its resource sees that resource's tokens and nothing else", async () => {
    await adapter.clients.upsert?.(client({ clientId: 'mcp-server', resourceServer: false, redirectUris: [], grantTypes: [] }))
    const forMcp = await (await redeem(await codeFor([MCP]))).json()
    expect((await introspect(forMcp.access_token, 'mcp-server')).aud).toBe(MCP)
    const unrestricted = await (await redeem(await codeFor([], 'jwt-rp'), undefined, 'jwt-rp')).json()
    expect(await introspect(unrestricted.access_token, 'mcp-server')).toEqual({ active: false })
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

// FR-C5: a token for a resource is that resource's, and the resource server holding it must not read the profile with it.
describe('UserInfo and a token issued for a resource', () => {
  const userinfo = (token: string) => provider.handle(new Request(`${ISSUER}/userinfo`, { headers: { authorization: `Bearer ${token}` } }))

  test('the token is refused at UserInfo', async () => {
    const issued = await (await redeem(await codeFor([MCP]))).json()
    const response = await userinfo(issued.access_token)
    expect(response.status).toBe(401)
    expect((await response.json()).error).toBe('invalid_token')
  })

  // OIDC Core §5.4: with no access token for UserInfo, the scope claims are the ID token's to carry.
  test('so the ID token carries the claims the scopes released', async () => {
    const issued = await (await redeem(await codeFor([MCP]))).json()
    expect(decodeJwt(issued.id_token)).toMatchObject({ sub: 'ada', name: 'Ada' })
  })

  test('and still does after a refresh', async () => {
    const issued = await (await redeem(await codeFor([MCP]))).json()
    const refreshed = await (await post('/token', { grant_type: 'refresh_token', refresh_token: issued.refresh_token })).json()
    expect(decodeJwt(refreshed.id_token)).toMatchObject({ sub: 'ada', name: 'Ada' })
  })

  test('without a resource the claims stay at UserInfo, and out of the ID token', async () => {
    const issued = await (await redeem(await codeFor([]))).json()
    expect(decodeJwt(issued.id_token).name).toBeUndefined()
    const response = await userinfo(issued.access_token)
    expect(response.status).toBe(200)
    expect((await response.json()).name).toBe('Ada')
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

describe('per-resource settings (FR-T2, FR-C19)', () => {
  const withResources = (
    resources: NonNullable<Parameters<typeof createProvider>[0]['resources']>,
    accessTokenClaims?: Parameters<typeof createProvider>[0]['accessTokenClaims']
  ) => {
    provider = createProvider({
      issuer: ISSUER,
      adapter,
      interactionUrl: `${ISSUER}/interaction`,
      scopes: ['openid', 'profile', 'offline_access', 'tools'],
      resources,
      ...(accessTokenClaims && { accessTokenClaims })
    })
  }

  test('a resource kept to some clients refuses any other at authorization, back to the client', async () => {
    withResources([{ uri: MCP }, { uri: API, clients: ['jwt-rp'] }])
    const refused = new URL((await authorize([API])).headers.get('location') as string)
    expect(refused.searchParams.get('error')).toBe('invalid_target')
    const allowed = await (await redeem(await codeFor([API], 'jwt-rp'), API, 'jwt-rp')).json()
    expect(decodeJwt(allowed.access_token).aud).toBe(API)
  })

  test('a resource kept to some clients refuses any other at the token endpoint, when the authorization named none', async () => {
    withResources([{ uri: MCP }, { uri: API, clients: ['jwt-rp'] }])
    const code = await codeFor([])
    const refused = await redeem(code, API)
    expect((await refused.json()).error).toBe('invalid_target')
    expect((await redeem(code, MCP)).status).toBe(200)
  })

  test('a resource set to jwt gets JWT access tokens for a client that asked for none, with its own lifetime', async () => {
    withResources([{ uri: MCP, accessTokenFormat: 'jwt', accessTokenTtl: 600 }])
    const tokens = await (await redeem(await codeFor([MCP]), MCP)).json()
    const claims = decodeJwt(tokens.access_token)
    expect(claims.aud).toBe(MCP)
    expect(tokens.expires_in).toBeLessThanOrEqual(600)
    expect(tokens.expires_in).toBeGreaterThan(590)
    expect((claims.exp as number) - (claims.iat as number)).toBe(600)
  })

  test("the host's claims ride on a JWT access token, and never replace one the provider sets", async () => {
    const told: unknown[] = []
    withResources([{ uri: MCP, accessTokenFormat: 'jwt' }], async token => {
      told.push(token)
      return { grant_id: token.grantId, sub: 'mallory', aud: 'elsewhere', cnf: { jkt: 'forged' }, scope: 'admin' }
    })
    const tokens = await (await redeem(await codeFor([MCP]), MCP)).json()
    const claims = decodeJwt(tokens.access_token)
    expect(claims.grant_id).toBeTruthy()
    expect(claims.sub).toBe('ada')
    expect(claims.aud).toBe(MCP)
    expect(claims.cnf).toBeUndefined()
    expect(claims.scope).toBe('openid offline_access tools')
    expect(told).toEqual([
      expect.objectContaining({
        clientId: 'rp',
        accountId: 'ada',
        grantId: claims.grant_id,
        resource: MCP,
        scopes: ['openid', 'offline_access', 'tools']
      })
    ])
  })

  test("an opaque access token never asks for the host's claims", async () => {
    let asked = false
    withResources([{ uri: MCP }], () => {
      asked = true
      return { grant_id: 'g' }
    })
    const tokens = await (await redeem(await codeFor([MCP]), MCP)).json()
    expect(tokens.access_token.split('.')).toHaveLength(1)
    expect(asked).toBe(false)
  })

  test('a resource lifetime that is not a positive whole number, or an empty client list, is refused at construction', () => {
    expect(() =>
      resolveConfig({ issuer: ISSUER, adapter, interactionUrl: `${ISSUER}/i`, resources: [{ uri: MCP, accessTokenTtl: 0 }] })
    ).toThrow(ConfigurationError)
    expect(() => resolveConfig({ issuer: ISSUER, adapter, interactionUrl: `${ISSUER}/i`, resources: [{ uri: MCP, clients: [] }] })).toThrow(
      ConfigurationError
    )
  })
})
