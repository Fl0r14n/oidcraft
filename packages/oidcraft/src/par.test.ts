import { beforeEach, describe, expect, test } from 'bun:test'
import { exportJWK, generateKeyPair, SignJWT } from 'jose'
import { memoryAdapter } from './adapters/memory'
import type { Adapter, Client } from './index'
import { createProvider, type Provider } from './provider'
import { base64url, sha256, token } from './random'

const ISSUER = 'https://op.example.com'
const REDIRECT = 'https://rp.example.com/cb'
const SECRET = 'shhh-a-long-enough-secret'

const client = (over: Partial<Client> = {}): Client => ({
  clientId: 'rp',
  clientSecret: SECRET,
  redirectUris: [REDIRECT],
  grantTypes: ['authorization_code'],
  responseTypes: ['code'],
  scopes: ['openid', 'profile'],
  tokenEndpointAuthMethod: 'client_secret_basic',
  createdAt: new Date(),
  updatedAt: new Date(),
  ...over
})

let adapter: Adapter
let provider: Provider
let challenge: string
let signing: { privateKey: CryptoKey; publicKey: CryptoKey }

const basic = (id = 'rp', secret = SECRET) => `Basic ${btoa(`${id}:${secret}`)}`

beforeEach(async () => {
  adapter = await memoryAdapter()
  signing = await generateKeyPair('ES256', { extractable: true })
  await adapter.clients.create?.(client())
  await adapter.clients.create?.(client({ clientId: 'strict', requirePushedAuthorizationRequests: true }))
  await adapter.clients.create?.(client({ clientId: 'signer', jwks: { keys: [await exportJWK(signing.publicKey)] } }))
  provider = createProvider({
    issuer: ISSUER,
    adapter,
    interactionUrl: `${ISSUER}/interaction`,
    features: { pushedAuthorizationRequests: true }
  })
  challenge = base64url(await sha256(token(32) + token(32)))
})

const requestParams = (over: Record<string, string> = {}) => ({
  client_id: 'rp',
  redirect_uri: REDIRECT,
  response_type: 'code',
  scope: 'openid profile',
  state: 'st',
  code_challenge: challenge,
  code_challenge_method: 'S256',
  ...over
})

const push = (params: Record<string, string>, headers: Record<string, string> = { authorization: basic() }) =>
  provider.handle(
    new Request(`${ISSUER}/request`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers },
      body: new URLSearchParams(params).toString()
    })
  )

const authorize = (params: Record<string, string>) => provider.handle(new Request(`${ISSUER}/authorize?${new URLSearchParams(params)}`))

describe('pushed authorization requests', () => {
  test('returns a single-use request_uri', async () => {
    const response = await push(requestParams())
    expect(response.status).toBe(201)
    const body = await response.json()
    expect(body.request_uri).toStartWith('urn:ietf:params:oauth:request_uri:')
    expect(body.expires_in).toBeGreaterThan(0)
    expect(response.headers.get('cache-control')).toBe('no-store')
  })

  test('the reference stands in for the pushed parameters', async () => {
    const { request_uri } = await (await push(requestParams())).json()
    const response = await authorize({ client_id: 'rp', request_uri })
    expect(response.status).toBe(303)
    expect(response.headers.get('location')).toContain(`${ISSUER}/interaction/`)
  })

  // RFC 9126 §4: otherwise a reference captured from the browser is replayable.
  test('a request_uri cannot be used twice', async () => {
    const { request_uri } = await (await push(requestParams())).json()
    await authorize({ client_id: 'rp', request_uri })
    const second = await authorize({ client_id: 'rp', request_uri })
    expect(second.status).toBe(400)
    expect((await second.json()).error_description).toContain('already used')
  })

  test('another client cannot redeem it', async () => {
    const { request_uri } = await (await push(requestParams())).json()
    const response = await authorize({ client_id: 'strict', request_uri })
    expect((await response.json()).error_description).toContain('different client')
  })

  test('an unknown request_uri is refused', async () => {
    const response = await authorize({ client_id: 'rp', request_uri: 'urn:ietf:params:oauth:request_uri:nope' })
    expect((await response.json()).error_description).toContain('unknown')
  })

  test('a request_uri this provider did not issue is refused', async () => {
    const response = await authorize({ client_id: 'rp', request_uri: 'https://evil.example.net/request' })
    expect((await response.json()).error_description).toContain('not issued here')
  })

  test('the endpoint requires client authentication', async () => {
    expect((await push(requestParams(), {})).status).toBe(401)
  })

  // §2.2: failing here means the user never sees it.
  test('a malformed request fails on the authenticated call, not in the browser', async () => {
    const response = await push(requestParams({ redirect_uri: 'https://evil.example.net/cb' }))
    expect(response.status).toBe(400)
    expect((await response.json()).error_description).toContain('not registered')
  })

  test('a pushed request cannot itself carry a request_uri', async () => {
    const response = await push(requestParams({ request_uri: 'urn:ietf:params:oauth:request_uri:x' }))
    expect((await response.json()).error_description).toContain('not allowed here')
  })

  test('client_id must match the authenticated client', async () => {
    const response = await push(requestParams({ client_id: 'strict' }))
    expect((await response.json()).error_description).toContain('does not match')
  })

  // RFC 9126 §2: the point of requiring it is that the front channel stops being an option.
  test('a client registered for PAR cannot use the front channel', async () => {
    const response = await authorize(requestParams({ client_id: 'strict' }))
    expect(response.status).toBe(400)
    expect((await response.json()).error_description).toContain('must push')
  })

  test('the endpoint is absent when the feature is off', async () => {
    const off = createProvider({ issuer: ISSUER, adapter })
    const response = await off.handle(new Request(`${ISSUER}/request`, { method: 'POST' }))
    expect(response.status).toBe(404)
  })
})

describe('request objects (JAR)', () => {
  // RFC 9101 §5: iss is the client, aud the provider. A mismatch is what the signature is for.
  const objectFor = async (claims: Record<string, unknown>, key = signing, issuer?: string) =>
    new SignJWT(claims)
      .setProtectedHeader({ alg: 'ES256' })
      .setIssuer(issuer ?? (claims.client_id as string) ?? 'signer')
      .setAudience(ISSUER)
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(key.privateKey)

  test('a signed request object supplies the parameters', async () => {
    const request = await objectFor({ ...requestParams({ client_id: 'signer' }) })
    const response = await authorize({ client_id: 'signer', request })
    expect(response.status).toBe(303)
    expect(response.headers.get('location')).toContain(`${ISSUER}/interaction/`)
  })

  test('an object signed by the wrong key is refused', async () => {
    const other = await generateKeyPair('ES256', { extractable: true })
    const request = await objectFor({ ...requestParams({ client_id: 'signer' }) }, other)
    const response = await authorize({ client_id: 'signer', request })
    expect((await response.json()).error_description).toContain('does not verify')
  })

  // RFC 9101 §6.1: otherwise the signature covers something other than what is acted on.
  test('a client_id disagreeing with the one outside is refused', async () => {
    const request = await objectFor({ ...requestParams({ client_id: 'rp' }) }, signing, 'signer')
    const response = await authorize({ client_id: 'signer', request })
    expect((await response.json()).error_description).toContain('does not match')
  })

  test('the object cannot nest another request', async () => {
    const request = await objectFor({ ...requestParams({ client_id: 'signer' }), request_uri: 'urn:x' })
    const response = await authorize({ client_id: 'signer', request })
    expect((await response.json()).error_description).toContain('may not contain')
  })

  test('a client with no registered keys cannot sign one', async () => {
    const request = await objectFor({ ...requestParams() })
    const response = await authorize({ client_id: 'rp', request })
    expect((await response.json()).error_description).toContain('no keys registered')
  })

  // The core does not fetch a URL the client chose (FR-A1); the host supplies a resolver instead.
  test('a jwks_uri client needs a host-supplied resolver', async () => {
    await adapter.clients.create?.(client({ clientId: 'remote', jwksUri: 'https://rp.example.com/jwks' }))
    const request = await objectFor({ ...requestParams({ client_id: 'remote' }) })
    const response = await authorize({ client_id: 'remote', request })
    expect((await response.json()).error_description).toContain('resolveClientJwks')

    const resolving = createProvider({
      issuer: ISSUER,
      adapter,
      interactionUrl: `${ISSUER}/interaction`,
      resolveClientJwks: async () => ({ keys: [await exportJWK(signing.publicKey)] })
    })
    const ok = await resolving.handle(new Request(`${ISSUER}/authorize?${new URLSearchParams({ client_id: 'remote', request })}`))
    expect(ok.status).toBe(303)
  })

  test('a request object works through PAR too', async () => {
    const request = await objectFor({ ...requestParams({ client_id: 'signer' }) })
    const pushed = await push({ request, client_id: 'signer' }, { authorization: basic('signer') })
    expect(pushed.status).toBe(201)
    const { request_uri } = await pushed.json()
    const response = await authorize({ client_id: 'signer', request_uri })
    expect(response.status).toBe(303)
  })
})

describe('discovery', () => {
  test('advertises request objects by value and not by reference', async () => {
    const metadata = await (await provider.handle(new Request(`${ISSUER}/.well-known/openid-configuration`))).json()
    expect(metadata.request_parameter_supported).toBe(true)
    expect(metadata.request_uri_parameter_supported).toBe(false)
    expect(metadata.pushed_authorization_request_endpoint).toBe(`${ISSUER}/request`)
  })
})
