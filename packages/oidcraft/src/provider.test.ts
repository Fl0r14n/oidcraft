import { describe, expect, test } from 'bun:test'
import { memoryAdapter } from './adapters/memory'
import { createProvider } from './provider'

const adapter = await memoryAdapter()
const provider = createProvider({ issuer: 'https://op.example.com', adapter })

const get = (path: string, init?: RequestInit) => provider.handle(new Request(`https://op.example.com${path}`, init))
const json = async (path: string, init?: RequestInit) => {
  const response = await get(path, init)
  return { status: response.status, body: await response.json(), headers: response.headers }
}

describe('discovery', () => {
  test('serves the openid-configuration document', async () => {
    const { status, body } = await json('/.well-known/openid-configuration')
    expect(status).toBe(200)
    expect(body.issuer).toBe('https://op.example.com')
    expect(body.jwks_uri).toBe('https://op.example.com/jwks')
    expect(body.token_endpoint).toBe('https://op.example.com/token')
  })

  test('also answers at the RFC 8414 path', async () => {
    const { body } = await json('/.well-known/oauth-authorization-server')
    expect(body.issuer).toBe('https://op.example.com')
  })

  // FR-C3 and FR-C1: PKCE is S256-only, and implicit is not offered at all.
  test('advertises S256 only and no implicit response type', async () => {
    const { body } = await json('/.well-known/openid-configuration')
    expect(body.code_challenge_methods_supported).toEqual(['S256'])
    expect(body.response_types_supported).not.toContain('token')
    expect(body.response_types_supported).not.toContain('code token')
  })

  // FR-C14: unconditional.
  test('advertises the iss authorization-response parameter', async () => {
    const { body } = await json('/.well-known/openid-configuration')
    expect(body.authorization_response_iss_parameter_supported).toBe(true)
  })

  // FR-C6: only what this configuration actually runs.
  test('omits endpoints whose feature is off', async () => {
    const { body } = await json('/.well-known/openid-configuration')
    expect(body).not.toHaveProperty('registration_endpoint')
    expect(body).not.toHaveProperty('device_authorization_endpoint')
    expect(body).toHaveProperty('revocation_endpoint')
  })

  test('advertises an endpoint once its feature is on', async () => {
    const withDevice = createProvider({
      issuer: 'https://op.example.com',
      adapter,
      features: { deviceFlow: true }
    })
    const response = await withDevice.handle(new Request('https://op.example.com/.well-known/openid-configuration'))
    const body = await response.json()
    expect(body.device_authorization_endpoint).toBe('https://op.example.com/device/authorize')
    expect(body.grant_types_supported).toContain('urn:ietf:params:oauth:grant-type:device_code')
  })

  // FR-R5 / G-8: a method the runtime cannot support is not advertised.
  test('omits mTLS client auth when the runtime cannot supply a certificate', async () => {
    const { body } = await json('/.well-known/openid-configuration')
    expect(body.token_endpoint_auth_methods_supported).not.toContain('tls_client_auth')
  })

  test('signing algorithms come from the keys that exist', async () => {
    const { body } = await json('/.well-known/openid-configuration')
    const keys = await adapter.keys.active()
    expect(body.id_token_signing_alg_values_supported).toEqual([keys[0]?.alg])
  })
})

describe('jwks', () => {
  test('serves the public keys', async () => {
    const { status, body } = await json('/jwks')
    expect(status).toBe(200)
    expect(body.keys).toHaveLength(1)
    expect(body.keys[0].kid).toBeTruthy()
  })

  test('never leaks private key material', async () => {
    const response = await get('/jwks')
    expect(await response.text()).not.toContain('"d"')
  })

  test('is cacheable', async () => {
    const response = await get('/jwks')
    expect(response.headers.get('cache-control')).toContain('max-age')
  })
})

describe('routing', () => {
  test('an unknown path is a 404 in the OAuth error shape', async () => {
    const { status, body } = await json('/nope')
    expect(status).toBe(404)
    expect(body.error).toBe('invalid_request')
  })

  test('a wrong method is a 405 that says which methods are allowed', async () => {
    const response = await get('/jwks', { method: 'POST' })
    expect(response.status).toBe(405)
    expect(response.headers.get('allow')).toBe('GET')
  })

  // Nothing advertised may be a stub. This held when most endpoints were unbuilt and it holds now
  // that none are; it is the assertion that stops metadata drifting ahead of behaviour.
  test('no routed endpoint answers 501, whatever features are on', async () => {
    const everything = createProvider({
      issuer: 'https://op.example.com',
      adapter,
      features: { deviceFlow: true, dynamicRegistration: true, pushedAuthorizationRequests: true, dpop: true }
    })
    const metadata = await (await everything.handle(new Request('https://op.example.com/.well-known/openid-configuration'))).json()
    const endpoints = Object.entries(metadata).filter(([key]) => key.endsWith('_endpoint')) as [string, string][]
    expect(endpoints.length).toBeGreaterThan(6)

    for (const [name, url] of endpoints) {
      for (const method of ['GET', 'POST']) {
        const response = await everything.handle(new Request(url, { method }))
        expect({ name, method, status: response.status }).not.toEqual({ name, method, status: 501 })
      }
    }
  })

  test('every route the default configuration advertises is implemented', async () => {
    const { body } = await json('/.well-known/openid-configuration')
    const endpoints = Object.entries(body).filter(([key]) => key.endsWith('_endpoint'))
    for (const [name, url] of endpoints as [string, string][]) {
      const path = new URL(url).pathname
      const response = await get(
        path,
        name === 'token_endpoint' || name.startsWith('revocation') || name.startsWith('introspection') ? { method: 'POST' } : {}
      )
      expect({ name, status: response.status }).not.toEqual({ name, status: 501 })
    }
  })

  test('an error response is never cached', async () => {
    const response = await get('/nope')
    expect(response.headers.get('cache-control')).toBe('no-store')
  })

  // NFR-S6: the document is served whatever host asked for it, but every URL in it is the
  // configured issuer. A request that could rewrite the issuer would rewrite the audience of
  // every token a client then accepts.
  test('a forged Host cannot rewrite the issuer or any endpoint', async () => {
    const response = await provider.handle(
      new Request('https://attacker.example.net/.well-known/openid-configuration', {
        headers: { host: 'attacker.example.net', 'x-forwarded-host': 'attacker.example.net' }
      })
    )
    expect(response.status).toBe(200)
    const body = await response.json()
    expect(body.issuer).toBe('https://op.example.com')
    expect(JSON.stringify(body)).not.toContain('attacker.example.net')
  })

  test('honours reconfigured routes', async () => {
    const custom = createProvider({ issuer: 'https://op.example.com', adapter, routes: { jwks: '/keys' } })
    expect((await custom.handle(new Request('https://op.example.com/keys'))).status).toBe(200)
    expect((await custom.handle(new Request('https://op.example.com/jwks'))).status).toBe(404)
  })
})
