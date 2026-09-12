import { describe, expect, test } from 'bun:test'
import { memoryAdapter } from './adapters/memory'
import { createProvider } from './provider'

/**
 * The discovery document against OIDC Discovery 1.0 §3 and RFC 8414 §2, cross-checked against what
 * the provider actually does. This is **not** certification — see conformance/README.md — but it
 * catches metadata drifting away from behaviour, which is the failure the real suite finds most.
 */
const ISSUER = 'https://op.example.com'
const adapter = await memoryAdapter()

const providerWith = (over: Parameters<typeof createProvider>[0] extends infer T ? Partial<T> : never = {}) =>
  createProvider({ issuer: ISSUER, adapter, ...over } as Parameters<typeof createProvider>[0])

const metadataOf = async (provider = providerWith()) =>
  (await (await provider.handle(new Request(`${ISSUER}/.well-known/openid-configuration`))).json()) as Record<string, unknown>

const REQUIRED = [
  'issuer',
  'authorization_endpoint',
  'token_endpoint',
  'jwks_uri',
  'response_types_supported',
  'subject_types_supported',
  'id_token_signing_alg_values_supported'
]

describe('discovery metadata', () => {
  test('carries every field OIDC Discovery 1.0 §3 requires', async () => {
    const metadata = await metadataOf()
    expect(REQUIRED.filter(field => metadata[field] === undefined)).toEqual([])
  })

  // OIDC Discovery 1.0 §4.3: the issuer in the document must equal the one that was requested.
  test('the issuer matches exactly, with no trailing slash', async () => {
    const metadata = await metadataOf()
    expect(metadata.issuer).toBe(ISSUER)
    expect(providerWith({ issuer: `${ISSUER}/` }).config.issuer).toBe(ISSUER)
  })

  test('every advertised endpoint is an absolute URL under the issuer', async () => {
    const metadata = await metadataOf()
    const endpoints = Object.entries(metadata).filter(([key]) => key.endsWith('_endpoint') || key === 'jwks_uri')
    expect(endpoints.length).toBeGreaterThan(4)
    for (const [name, value] of endpoints) {
      expect({ name, ok: typeof value === 'string' && (value as string).startsWith(`${ISSUER}/`) }).toEqual({ name, ok: true })
    }
  })

  test('every advertised signing algorithm has a key behind it', async () => {
    const metadata = await metadataOf()
    const jwks = (await (await providerWith().handle(new Request(`${ISSUER}/jwks`))).json()) as { keys: { alg: string }[] }
    const available = new Set(jwks.keys.map(key => key.alg))
    for (const alg of metadata.id_token_signing_alg_values_supported as string[]) {
      expect({ alg, hasKey: available.has(alg) }).toEqual({ alg, hasKey: true })
    }
  })

  test('advertised scopes include openid and nothing undeclared', async () => {
    const metadata = await metadataOf()
    expect(metadata.scopes_supported).toContain('openid')
  })

  // RFC 9700 §2.1.2 and OAuth 2.1: neither may be offered.
  test('no response type issues a token from the authorization endpoint', async () => {
    const metadata = await metadataOf()
    for (const responseType of metadata.response_types_supported as string[]) {
      expect({ responseType, carriesToken: responseType.split(' ').includes('token') }).toEqual({ responseType, carriesToken: false })
    }
  })

  test('the password and implicit grants are not offered', async () => {
    const metadata = await metadataOf()
    const grants = metadata.grant_types_supported as string[]
    expect(grants).not.toContain('password')
    expect(grants).not.toContain('implicit')
  })

  // FR-C3: advertising `plain` would be advertising a downgrade.
  test('only S256 is advertised for PKCE', async () => {
    expect((await metadataOf()).code_challenge_methods_supported).toEqual(['S256'])
  })

  test('an advertised token_endpoint_auth_method is one the provider will accept', async () => {
    const metadata = await metadataOf()
    const advertised = metadata.token_endpoint_auth_methods_supported as string[]
    expect(advertised.length).toBeGreaterThan(0)
    for (const method of advertised) expect(providerWith().config.clientAuthMethods).toContain(method as never)
  })

  test('RFC 8414 metadata agrees with the OIDC document', async () => {
    const oidc = await metadataOf()
    const oauth = (await (await providerWith().handle(new Request(`${ISSUER}/.well-known/oauth-authorization-server`))).json()) as Record<
      string,
      unknown
    >
    expect(oauth.issuer).toBe(oidc.issuer)
    expect(oauth.token_endpoint).toBe(oidc.token_endpoint)
  })

  test('a disabled feature is absent from the metadata, not advertised and broken', async () => {
    const metadata = await metadataOf(providerWith({ features: { revocation: false, introspection: false } }))
    expect(metadata).not.toHaveProperty('revocation_endpoint')
    expect(metadata).not.toHaveProperty('introspection_endpoint')
  })

  test('a disabled endpoint is not routed either', async () => {
    const provider = providerWith({ features: { revocation: false } })
    const response = await provider.handle(new Request(`${ISSUER}/revoke`, { method: 'POST' }))
    expect(response.status).toBe(404)
  })

  test('the document is cacheable and the JWKS is too', async () => {
    const provider = providerWith()
    for (const path of ['/.well-known/openid-configuration', '/jwks']) {
      const response = await provider.handle(new Request(`${ISSUER}${path}`))
      expect({ path, cache: response.headers.get('cache-control')?.includes('max-age') }).toEqual({ path, cache: true })
    }
  })
})
