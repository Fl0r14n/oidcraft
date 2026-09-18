import { describe, expect, test } from 'bun:test'
import { memoryAdapter } from './adapters/memory'
import { createProvider } from './provider'

/**
 * The discovery document against OIDC Discovery 1.0 §3 and RFC 8414 §2, cross-checked against what
 * the provider actually does. This is **not** certification — see conformance/README.md — but it
 * catches metadata drifting away from behaviour, which is the failure the real suite finds most.
 */
const ISSUER = 'https://op.example.com'
const REDIRECT = 'https://rp.example.com/cb'
const SECRET = 'a-long-enough-client-secret'
const CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'
const adapter = await memoryAdapter()

/** A client registered for everything the metadata claims, so the claims can be tried. */
const advertisedClient = async (provider: ReturnType<typeof createProvider>) => {
  const metadata = (await (await provider.handle(new Request(`${ISSUER}/.well-known/openid-configuration`))).json()) as Record<
    string,
    string[]
  >
  const clientId = 'advertised'
  if (!(await adapter.clients.find(clientId))) {
    await adapter.clients.create?.({
      clientId,
      clientSecret: SECRET,
      redirectUris: [REDIRECT],
      grantTypes: metadata.grant_types_supported as string[],
      responseTypes: metadata.response_types_supported as string[],
      scopes: metadata.scopes_supported as string[],
      tokenEndpointAuthMethod: 'client_secret_basic',
      createdAt: new Date(),
      updatedAt: new Date()
    })
  }
  return clientId
}

const providerWith = (over: Parameters<typeof createProvider>[0] extends infer T ? Partial<T> : never = {}) =>
  createProvider({ issuer: ISSUER, adapter, interactionUrl: `${ISSUER}/interaction`, ...over } as Parameters<typeof createProvider>[0])

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

  /**
   * The assertion that matters, and the one that was missing: every advertised value is *tried*,
   * not merely read. Discovery advertised `id_token`, `code id_token`, `client_credentials` and
   * `private_key_jwt` for a while, all of which the code refused — the earlier tests read those
   * lists and checked their shape, which proves nothing about whether they are true (FR-C6).
   */
  test('every advertised response type is accepted', async () => {
    const provider = providerWith()
    const client = await advertisedClient(provider)
    const metadata = await metadataOf(provider)

    for (const responseType of metadata.response_types_supported as string[]) {
      const response = await provider.handle(
        new Request(
          `${ISSUER}/authorize?${new URLSearchParams({
            client_id: client,
            redirect_uri: REDIRECT,
            response_type: responseType,
            scope: 'openid',
            code_challenge: CHALLENGE,
            code_challenge_method: 'S256'
          })}`
        )
      )
      const error = new URL(response.headers.get('location') ?? REDIRECT, ISSUER).searchParams.get('error')
      expect({ responseType, error }).toEqual({ responseType, error: null })
    }
  })

  test('every advertised grant type reaches its handler', async () => {
    const provider = providerWith()
    const client = await advertisedClient(provider)
    const metadata = await metadataOf(provider)

    for (const grantType of metadata.grant_types_supported as string[]) {
      const response = await provider.handle(
        new Request(`${ISSUER}/token`, {
          method: 'POST',
          headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: `Basic ${btoa(`${client}:${SECRET}`)}` },
          body: new URLSearchParams({ grant_type: grantType, scope: 'profile' }).toString()
        })
      )
      const body = (await response.json()) as { error?: string }
      // A handler that rejects the *request* is fine; one that rejects the grant type is not.
      expect({ grantType, error: body.error }).not.toEqual({ grantType, error: 'unsupported_grant_type' })
      expect({ grantType, error: body.error }).not.toEqual({ grantType, error: 'unauthorized_client' })
    }
  })

  test('every advertised client authentication method is implemented', async () => {
    const provider = providerWith()
    const metadata = await metadataOf(provider)

    for (const method of metadata.token_endpoint_auth_methods_supported as string[]) {
      const clientId = `probe-${method}`
      await adapter.clients.create?.({
        clientId,
        ...(method === 'none' ? {} : { clientSecret: SECRET }),
        redirectUris: [REDIRECT],
        grantTypes: ['authorization_code'],
        responseTypes: ['code'],
        scopes: ['openid'],
        tokenEndpointAuthMethod: method as never,
        createdAt: new Date(),
        updatedAt: new Date()
      })

      const response = await provider.handle(
        new Request(`${ISSUER}/token`, {
          method: 'POST',
          headers: { 'content-type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ grant_type: 'authorization_code', client_id: clientId, code: 'x' }).toString()
        })
      )
      const body = (await response.json()) as { error_description?: string }
      expect({ method, unimplemented: body.error_description?.includes('not implemented') ?? false }).toEqual({
        method,
        unimplemented: false
      })
    }
  })

  test('the document is cacheable and the JWKS is too', async () => {
    const provider = providerWith()
    for (const path of ['/.well-known/openid-configuration', '/jwks']) {
      const response = await provider.handle(new Request(`${ISSUER}${path}`))
      expect({ path, cache: response.headers.get('cache-control')?.includes('max-age') }).toEqual({ path, cache: true })
    }
  })
})
