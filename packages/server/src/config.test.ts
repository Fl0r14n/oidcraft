import { describe, expect, test } from 'bun:test'
import { memoryAdapter } from './adapters/memory'
import { resolveConfig } from './config'
import { ConfigurationError } from './errors'

const adapter = await memoryAdapter()
const base = { issuer: 'https://op.example.com', adapter }

const problemsOf = (fn: () => unknown) => {
  try {
    fn()
    return null
  } catch (error) {
    return error instanceof ConfigurationError ? error.problems : [String(error)]
  }
}

describe('resolveConfig', () => {
  test('accepts a minimal configuration and fills the defaults', () => {
    const config = resolveConfig(base)
    expect(config.issuer).toBe('https://op.example.com')
    expect(config.routes.jwks).toBe('/jwks')
    expect(config.ttl.accessToken).toBe(900)
    expect(config.scopes).toContain('openid')
    expect(config.features.dynamicRegistration).toBe(false)
  })

  test('strips a trailing slash so the issuer matches the token claim exactly', () => {
    expect(resolveConfig({ ...base, issuer: 'https://op.example.com/' }).issuer).toBe('https://op.example.com')
  })

  test('allows http on loopback but nowhere else', () => {
    expect(resolveConfig({ ...base, issuer: 'http://localhost:3001' }).issuer).toBe('http://localhost:3001')
    expect(problemsOf(() => resolveConfig({ ...base, issuer: 'http://op.example.com' }))?.join()).toContain('must be https')
  })

  test('rejects an issuer that is not an absolute URL', () => {
    expect(problemsOf(() => resolveConfig({ ...base, issuer: '/op' }))?.join()).toContain('not an absolute URL')
  })

  test('rejects an issuer carrying a query or fragment', () => {
    expect(problemsOf(() => resolveConfig({ ...base, issuer: 'https://op.example.com/?x=1' }))?.join()).toContain(
      'query string or fragment'
    )
  })

  test('rejects scopes without openid', () => {
    expect(problemsOf(() => resolveConfig({ ...base, scopes: ['profile'] }))?.join()).toContain('must include "openid"')
  })

  test('rejects colliding routes', () => {
    const problems = problemsOf(() => resolveConfig({ ...base, routes: { token: '/authorize' } }))
    expect(problems?.join()).toContain('must be distinct')
  })

  test('rejects a non-absolute route', () => {
    expect(problemsOf(() => resolveConfig({ ...base, routes: { token: 'token' } }))?.join()).toContain('absolute path')
  })

  test('rejects a non-positive ttl', () => {
    expect(problemsOf(() => resolveConfig({ ...base, ttl: { accessToken: 0 } }))?.join()).toContain('positive whole number')
  })

  // FR-R5 / G-8: the runtime cannot supply a client certificate, so the method cannot work.
  test('rejects mTLS client auth when the runtime supplies no certificate', () => {
    const problems = problemsOf(() => resolveConfig({ ...base, clientAuthMethods: ['tls_client_auth'] }))
    expect(problems?.join()).toContain('supplies no RequestContext.clientCertificate')
  })

  test('accepts mTLS client auth once the capability is declared', () => {
    const config = resolveConfig({ ...base, clientAuthMethods: ['tls_client_auth'], capabilities: { clientCertificate: true } })
    expect(config.clientAuthMethods).toEqual(['tls_client_auth'])
  })

  test('rejects dynamic registration without an adapter that can create clients', async () => {
    const full = await memoryAdapter()
    const crippled = { ...full, clients: { find: full.clients.find } }
    const problems = problemsOf(() => resolveConfig({ ...base, adapter: crippled, features: { dynamicRegistration: true } }))
    expect(problems?.join()).toContain('clients store implements create')
  })

  test('reports every problem at once rather than the first', () => {
    const problems = problemsOf(() => resolveConfig({ ...base, issuer: 'http://op.example.com', scopes: ['profile'] }))
    expect(problems?.length).toBe(2)
  })
})
