import { beforeEach, describe, expect, test } from 'bun:test'
import { exportJWK, generateKeyPair, SignJWT } from 'jose'
import { memoryAdapter } from './adapters/memory'
import type { Adapter, Client } from './index'
import { createProvider, type Provider } from './provider'

const ISSUER = 'https://op.example.com'
const SECRET = 'a-long-enough-client-secret'
const ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'

const client = (over: Partial<Client> = {}): Client => ({
  clientId: 'api',
  clientSecret: SECRET,
  redirectUris: ['https://rp.example.com/cb'],
  grantTypes: ['client_credentials', 'authorization_code'],
  responseTypes: ['code'],
  scopes: ['openid', 'profile', 'orders'],
  tokenEndpointAuthMethod: 'client_secret_basic',
  createdAt: new Date(),
  updatedAt: new Date(),
  ...over
})

let adapter: Adapter
let provider: Provider
let signing: { privateKey: CryptoKey; publicKey: CryptoKey }

const post = (body: Record<string, string>, headers: Record<string, string> = {}) =>
  provider.handle(
    new Request(`${ISSUER}/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers },
      body: new URLSearchParams(body).toString()
    })
  )

const basic = (id = 'api', secret = SECRET) => `Basic ${btoa(`${id}:${secret}`)}`

beforeEach(async () => {
  adapter = await memoryAdapter()
  signing = await generateKeyPair('ES256', { extractable: true })
  await adapter.clients.create?.(client())
  const { clientSecret: _omitted, ...publicClient } = client({ clientId: 'public-api', tokenEndpointAuthMethod: 'none' })
  await adapter.clients.create?.(publicClient)
  await adapter.clients.create?.(
    client({ clientId: 'pkj', tokenEndpointAuthMethod: 'private_key_jwt', jwks: { keys: [await exportJWK(signing.publicKey)] } })
  )
  await adapter.clients.create?.(client({ clientId: 'csj', tokenEndpointAuthMethod: 'client_secret_jwt' }))
  provider = createProvider({ issuer: ISSUER, adapter, scopes: ['openid', 'profile', 'orders'] })
})

describe('client credentials grant', () => {
  test('issues an access token for the client itself', async () => {
    const response = await post({ grant_type: 'client_credentials', scope: 'orders' }, { authorization: basic() })
    expect(response.status).toBe(200)
    const body = await response.json()
    expect(body.access_token).toBeTruthy()
    expect(body.scope).toBe('orders')
  })

  // There is no user, so there is nothing to make claims about and nothing to come back for.
  test('issues neither an ID token nor a refresh token', async () => {
    const body = await (await post({ grant_type: 'client_credentials' }, { authorization: basic() })).json()
    expect(body.id_token).toBeUndefined()
    expect(body.refresh_token).toBeUndefined()
  })

  test('refuses the openid scope, which would be meaningless', async () => {
    const body = await (await post({ grant_type: 'client_credentials', scope: 'openid' }, { authorization: basic() })).json()
    expect(body.error).toBe('invalid_scope')
  })

  test('refuses a scope the client may not have', async () => {
    const body = await (await post({ grant_type: 'client_credentials', scope: 'admin' }, { authorization: basic() })).json()
    expect(body.error).toBe('invalid_scope')
  })

  // A public client has no credential of its own, so "the client itself" means nothing.
  test('is refused for a public client', async () => {
    const body = await (await post({ grant_type: 'client_credentials', client_id: 'public-api' })).json()
    expect(body.error).toBe('invalid_client')
  })

  test('the token identifies no end user', async () => {
    const body = await (await post({ grant_type: 'client_credentials', scope: 'orders' }, { authorization: basic() })).json()
    const stored = await adapter.artifacts.find('access_token', body.access_token)
    expect(stored?.accountId).toBeUndefined()

    const userinfo = await provider.handle(new Request(`${ISSUER}/userinfo`, { headers: { authorization: `Bearer ${body.access_token}` } }))
    expect(userinfo.status).toBe(401)
  })
})

describe('private_key_jwt', () => {
  const assertion = async (over: Record<string, unknown> = {}, key = signing, clientId = 'pkj') => {
    const builder = new SignJWT({ jti: crypto.randomUUID(), ...over })
      .setProtectedHeader({ alg: 'ES256' })
      .setIssuedAt()
      .setExpirationTime('2m')
    if (!('iss' in over)) builder.setIssuer(clientId)
    if (!('sub' in over)) builder.setSubject(clientId)
    if (!('aud' in over)) builder.setAudience(`${ISSUER}/token`)
    return builder.sign(key.privateKey)
  }

  const authenticate = async (jwt: string, extra: Record<string, string> = {}) =>
    post({ grant_type: 'client_credentials', scope: 'orders', client_assertion_type: ASSERTION_TYPE, client_assertion: jwt, ...extra })

  test('authenticates with a signed assertion, and needs no client_id', async () => {
    const response = await authenticate(await assertion())
    expect(response.status).toBe(200)
    expect((await response.json()).access_token).toBeTruthy()
  })

  test('accepts the issuer as the audience too', async () => {
    expect((await authenticate(await assertion({ aud: ISSUER }))).status).toBe(200)
  })

  // Without the audience check, every provider a client talks to could impersonate it elsewhere.
  test('an assertion made out to another provider is refused', async () => {
    const body = await (await authenticate(await assertion({ aud: 'https://other.example.com/token' }))).json()
    expect(body.error).toBe('invalid_client')
  })

  test('an assertion signed by the wrong key is refused', async () => {
    const other = await generateKeyPair('ES256', { extractable: true })
    expect((await (await authenticate(await assertion({}, other))).json()).error).toBe('invalid_client')
  })

  test('an assertion naming a different client is refused', async () => {
    expect((await (await authenticate(await assertion({ sub: 'api' }))).json()).error).toBe('invalid_client')
  })

  // NFR-S5: otherwise a captured assertion is reusable until it expires.
  test('an assertion cannot be replayed', async () => {
    const once = await assertion()
    expect((await authenticate(once)).status).toBe(200)
    const replayed = await (await authenticate(once)).json()
    expect(replayed.error_description).toContain('already been used')
  })

  test('an assertion without a jti is refused', async () => {
    const noJti = await new SignJWT({})
      .setProtectedHeader({ alg: 'ES256' })
      .setIssuer('pkj')
      .setSubject('pkj')
      .setAudience(`${ISSUER}/token`)
      .setIssuedAt()
      .setExpirationTime('2m')
      .sign(signing.privateKey)
    expect((await (await authenticate(noJti)).json()).error_description).toContain('jti')
  })

  test('a long-lived assertion is refused', async () => {
    const long = await new SignJWT({ jti: crypto.randomUUID() })
      .setProtectedHeader({ alg: 'ES256' })
      .setIssuer('pkj')
      .setSubject('pkj')
      .setAudience(`${ISSUER}/token`)
      .setIssuedAt()
      .setExpirationTime('2h')
      .sign(signing.privateKey)
    expect((await (await authenticate(long)).json()).error_description).toContain('longer than')
  })

  test('the wrong client_assertion_type is refused', async () => {
    const body = await (
      await post({
        grant_type: 'client_credentials',
        client_assertion_type: 'urn:example:something-else',
        client_assertion: await assertion()
      })
    ).json()
    expect(body.error_description).toContain('client_assertion_type must be')
  })

  test('an assertion alongside a secret is refused rather than resolved', async () => {
    const body = await (
      await post(
        { grant_type: 'client_credentials', client_assertion_type: ASSERTION_TYPE, client_assertion: await assertion() },
        { authorization: basic() }
      )
    ).json()
    expect(body.error_description).toContain('alongside a secret')
  })

  test('a client registered for a secret cannot use an assertion instead', async () => {
    const forApi = await assertion({}, signing, 'api')
    const body = await (await authenticate(forApi)).json()
    expect(body.error).toBe('invalid_client')
  })
})

describe('client_secret_jwt', () => {
  const hmacAssertion = async (secret = SECRET) =>
    new SignJWT({ jti: crypto.randomUUID() })
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuer('csj')
      .setSubject('csj')
      .setAudience(`${ISSUER}/token`)
      .setIssuedAt()
      .setExpirationTime('2m')
      .sign(new TextEncoder().encode(secret))

  test('authenticates with an HMAC assertion', async () => {
    const response = await post({
      grant_type: 'client_credentials',
      scope: 'orders',
      client_assertion_type: ASSERTION_TYPE,
      client_assertion: await hmacAssertion()
    })
    expect(response.status).toBe(200)
  })

  test('the wrong secret is refused', async () => {
    const body = await (
      await post({
        grant_type: 'client_credentials',
        client_assertion_type: ASSERTION_TYPE,
        client_assertion: await hmacAssertion('not-the-secret')
      })
    ).json()
    expect(body.error).toBe('invalid_client')
  })

  // Confusing the two is how a shared secret gets accepted where a public key was registered.
  test('an HMAC assertion is refused for a private_key_jwt client', async () => {
    const forPkj = await new SignJWT({ jti: crypto.randomUUID() })
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuer('pkj')
      .setSubject('pkj')
      .setAudience(`${ISSUER}/token`)
      .setIssuedAt()
      .setExpirationTime('2m')
      .sign(new TextEncoder().encode(SECRET))
    const body = await (
      await post({ grant_type: 'client_credentials', client_assertion_type: ASSERTION_TYPE, client_assertion: forPkj })
    ).json()
    expect(body.error).toBe('invalid_client')
  })
})
