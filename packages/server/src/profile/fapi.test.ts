import { beforeEach, describe, expect, test } from 'bun:test'
import { randomString, sha256 } from '@oidcraft/core'
import { base64url, decodeProtectedHeader, exportJWK, generateKeyPair, SignJWT } from 'jose'
import type { FullAdapter } from '../adapter'
import { memoryAdapter } from '../adapters/memory'
import { ASSERTION_TYPE } from '../clients/assertion'
import { ConfigurationError } from '../errors'
import type { Client } from '../index'
import { generateKey, staticKeyStore } from '../keys/keys'
import { createProvider, type Provider } from '../provider'
import { SESSION_COOKIE } from '../session/session'

const ISSUER = 'https://op.example.com'
const REDIRECT = 'https://rp.example.com/cb'

type KeyPair = { privateKey: CryptoKey; publicKey: CryptoKey }

let adapter: FullAdapter
let provider: Provider
let clientKey: KeyPair
let dpopKey: KeyPair
let verifier: string

const accounts = {
  async find(accountId: string) {
    return { accountId, claims: {} }
  },
  async claims() {
    return {}
  }
}

const fapiClient = async (over: Partial<Client> = {}): Promise<Client> => ({
  clientId: 'bank',
  redirectUris: [REDIRECT],
  grantTypes: ['authorization_code', 'refresh_token'],
  responseTypes: ['code'],
  scopes: ['openid', 'offline_access'],
  tokenEndpointAuthMethod: 'private_key_jwt',
  jwks: { keys: [{ ...(await exportJWK(clientKey.publicKey)), alg: 'ES256', use: 'sig' }] },
  createdAt: new Date(),
  updatedAt: new Date(),
  ...over
})

const build = (over: Record<string, unknown> = {}) =>
  createProvider({
    issuer: ISSUER,
    adapter,
    interactionUrl: `${ISSUER}/interaction`,
    features: { dpop: true, pushedAuthorizationRequests: true },
    ...over
  } as Parameters<typeof createProvider>[0])

beforeEach(async () => {
  const [es256, rs256] = await Promise.all([generateKey('ES256'), generateKey('RS256')])
  // RS256 first, so a token signed with anything else was chosen by the profile, not by the order.
  adapter = await memoryAdapter({ accounts, keys: staticKeyStore([rs256, es256]) })
  clientKey = await generateKeyPair('ES256', { extractable: true })
  dpopKey = await generateKeyPair('ES256', { extractable: true })
  verifier = randomString() + randomString()
  await adapter.clients.upsert?.(await fapiClient())
  provider = build({ profile: 'fapi2' })
})

const assertion = async (over: { aud?: string; iat?: number; nbf?: number; key?: KeyPair; alg?: string } = {}) => {
  const now = Math.floor(Date.now() / 1000)
  return new SignJWT({ jti: randomString(), ...(over.nbf !== undefined && { nbf: over.nbf }) })
    .setProtectedHeader({ alg: over.alg ?? 'ES256' })
    .setIssuer('bank')
    .setSubject('bank')
    .setAudience(over.aud ?? ISSUER)
    .setIssuedAt(over.iat ?? now)
    .setExpirationTime(now + 60)
    .sign((over.key ?? clientKey).privateKey)
}

const dpop = async (method: string, uri: string, key = dpopKey) =>
  new SignJWT({ jti: randomString(), htm: method, htu: uri })
    .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: await exportJWK(key.publicKey) })
    .setIssuedAt()
    .sign(key.privateKey)

const post = (path: string, body: Record<string, string>, headers: Record<string, string> = {}) =>
  provider.handle(
    new Request(`${ISSUER}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers },
      body: new URLSearchParams(body).toString()
    })
  )

const authenticated = async (body: Record<string, string>) => ({
  ...body,
  client_assertion_type: ASSERTION_TYPE,
  client_assertion: await assertion()
})

const authorizationParams = async () => ({
  client_id: 'bank',
  redirect_uri: REDIRECT,
  response_type: 'code',
  scope: 'openid offline_access',
  code_challenge: base64url.encode(await sha256(verifier)),
  code_challenge_method: 'S256'
})

const push = async (withDpop = true) => {
  const response = await post(
    '/request',
    await authenticated(await authorizationParams()),
    withDpop ? { dpop: await dpop('POST', `${ISSUER}/request`) } : {}
  )
  return (await response.json()) as { request_uri: string }
}

const codeFor = async (requestUri: string) => {
  let response = await provider.handle(
    new Request(`${ISSUER}/authorize?${new URLSearchParams({ client_id: 'bank', request_uri: requestUri })}`)
  )
  let cookie = ''
  for (let i = 0; i < 3; i++) {
    const location = new URL(response.headers.get('location') as string)
    if (!location.pathname.startsWith('/interaction/')) return location.searchParams.get('code') as string
    const id = location.pathname.split('/').pop() as string
    const view = await provider.interactions.find(id)
    const done = await provider.interactions.complete(
      id,
      view.kind === 'login' ? { login: { accountId: 'ada' } } : { consent: { scopes: view.scopes } }
    )
    if (done.setCookie) cookie = `${SESSION_COOKIE}=${done.setCookie.split('=')[1]?.split(';')[0]}`
    response = await provider.handle(new Request(done.redirectTo, { headers: cookie ? { cookie } : {} }))
  }
  throw new Error('never reached the redirect')
}

const redeem = async (code: string, withDpop = true) =>
  post(
    '/token',
    await authenticated({ grant_type: 'authorization_code', code, redirect_uri: REDIRECT, code_verifier: verifier }),
    withDpop ? { dpop: await dpop('POST', `${ISSUER}/token`) } : {}
  )

const refresh = async (token: string) =>
  post('/token', await authenticated({ grant_type: 'refresh_token', refresh_token: token }), {
    dpop: await dpop('POST', `${ISSUER}/token`)
  })

describe('FR-C21: a provider under FAPI 2.0 refuses to start without what the profile needs', () => {
  test('pushed authorization requests', () => {
    expect(() => build({ profile: 'fapi2', features: { dpop: true } })).toThrow(/pushedAuthorizationRequests/)
  })

  test('a way to sender-constrain tokens', () => {
    expect(() => build({ profile: 'fapi2', features: { pushedAuthorizationRequests: true } })).toThrow(/sender-constrained/)
  })

  test('a client authentication method that is not a shared secret', () => {
    expect(() => build({ profile: 'fapi2', clientAuthMethods: ['client_secret_basic', 'none'] })).toThrow(ConfigurationError)
  })

  test('a profile it does not know', () => {
    expect(() => build({ profile: 'fapi1' })).toThrow(/profile fapi1/)
  })
})

describe('FR-C21: clients the profile does not allow', () => {
  test('the management API refuses a shared secret or an http redirect for a web client', async () => {
    const management = build().management.clients
    const base = { redirectUris: [REDIRECT], grantTypes: ['authorization_code'], responseTypes: ['code'], scopes: ['openid'] }
    expect(management.create({ ...base, clientId: 'a', profile: 'fapi2', tokenEndpointAuthMethod: 'client_secret_basic' })).rejects.toThrow(
      /client_secret_basic/
    )
    expect(
      management.create({
        ...base,
        clientId: 'b',
        profile: 'fapi2',
        tokenEndpointAuthMethod: 'private_key_jwt',
        redirectUris: ['http://rp.example.com/cb']
      })
    ).rejects.toThrow(/http/)
    expect(await management.create({ ...base, clientId: 'c', tokenEndpointAuthMethod: 'client_secret_basic' })).toBeTruthy()
  })

  test('a public client is refused at the authorization endpoint under a provider-wide profile', async () => {
    await adapter.clients.upsert?.({ ...(await fapiClient()), clientId: 'spa', tokenEndpointAuthMethod: 'none', jwks: undefined as never })
    const params = new URLSearchParams({ ...(await authorizationParams()), client_id: 'spa' })
    const response = await provider.handle(new Request(`${ISSUER}/authorize?${params}`))
    expect(response.status).toBe(401)
    expect((await response.json()).error).toBe('invalid_client')
  })

  test('an authorization request that was not pushed is refused', async () => {
    const response = await provider.handle(new Request(`${ISSUER}/authorize?${new URLSearchParams(await authorizationParams())}`))
    expect(response.status).toBe(400)
    expect((await response.json()).error_description).toContain('must push')
  })
})

describe('FR-C21: the flow under the profile', () => {
  test('PAR, a DPoP-bound code, and a sender-constrained token signed with a profile algorithm', async () => {
    const response = await redeem(await codeFor((await push()).request_uri))
    expect(response.status).toBe(200)
    const body = await response.json()
    expect(body.token_type).toBe('DPoP')
    expect(decodeProtectedHeader(body.id_token).alg).toBe('ES256')
  })

  test('a token request with neither a DPoP proof nor a certificate is refused', async () => {
    const code = await codeFor((await push(false)).request_uri)
    expect((await (await redeem(code, false)).json()).error_description).toContain('sender-constrained')
  })

  test('a DPoP token request for a code the push did not bind to a key is refused', async () => {
    const code = await codeFor((await push(false)).request_uri)
    expect((await (await redeem(code)).json()).error_description).toContain('dpop_jkt')
  })

  // FR-T3's one exception: the client keeps one refresh token, so a dropped response loses nothing.
  test('the refresh token does not rotate, and presenting it again is not a replay', async () => {
    const issued = await (await redeem(await codeFor((await push()).request_uri))).json()
    const first = await (await refresh(issued.refresh_token)).json()
    expect(first.refresh_token).toBe(issued.refresh_token)
    const second = await refresh(issued.refresh_token)
    expect(second.status).toBe(200)
    expect((await second.json()).access_token).not.toBe(first.access_token)
  })
})

describe('FR-C21: client assertions under the profile', () => {
  const pushWith = async (clientAssertion: string) =>
    post('/request', { ...(await authorizationParams()), client_assertion_type: ASSERTION_TYPE, client_assertion: clientAssertion })

  test('the audience must be the issuer alone, not the token endpoint', async () => {
    expect((await pushWith(await assertion({ aud: `${ISSUER}/token` }))).status).toBe(401)
    expect((await pushWith(await assertion())).status).toBe(201)
  })

  test('an iat up to ten seconds ahead is accepted, an nbf over a minute old is not', async () => {
    const now = Math.floor(Date.now() / 1000)
    expect((await pushWith(await assertion({ iat: now + 8 }))).status).toBe(201)
    expect((await pushWith(await assertion({ nbf: now - 120 }))).status).toBe(401)
  })

  test('an algorithm outside PS256, ES256 and EdDSA is refused', async () => {
    const es384 = await generateKeyPair('ES384', { extractable: true })
    await adapter.clients.upsert?.(
      await fapiClient({ jwks: { keys: [{ ...(await exportJWK(es384.publicKey)), alg: 'ES384', use: 'sig' }] } })
    )
    expect((await pushWith(await assertion({ key: es384, alg: 'ES384' }))).status).toBe(401)
  })
})

describe('FR-C21: one client under the profile, the rest as before', () => {
  beforeEach(async () => {
    provider = build()
    await adapter.clients.upsert?.(await fapiClient({ profile: 'fapi2' }))
    await adapter.clients.upsert?.({
      ...(await fapiClient()),
      clientId: 'spa',
      tokenEndpointAuthMethod: 'none',
      jwks: undefined as never
    })
  })

  test('the FAPI client must push; a public client beside it need not', async () => {
    const fapi = await provider.handle(new Request(`${ISSUER}/authorize?${new URLSearchParams(await authorizationParams())}`))
    expect((await fapi.json()).error_description).toContain('must push')
    const spa = await provider.handle(
      new Request(`${ISSUER}/authorize?${new URLSearchParams({ ...(await authorizationParams()), client_id: 'spa' })}`)
    )
    expect(spa.status).toBe(303)
  })

  test('discovery does not narrow for a per-client profile', async () => {
    const metadata = await (await provider.handle(new Request(`${ISSUER}/.well-known/openid-configuration`))).json()
    expect(metadata.require_pushed_authorization_requests).toBe(false)
    expect(metadata.token_endpoint_auth_methods_supported).toContain('none')
  })
})

describe('FR-C21: discovery under a provider-wide profile', () => {
  test('advertises only what the profile accepts', async () => {
    const metadata = await (await provider.handle(new Request(`${ISSUER}/.well-known/openid-configuration`))).json()
    expect(metadata.require_pushed_authorization_requests).toBe(true)
    expect(metadata.token_endpoint_auth_methods_supported).toEqual(['private_key_jwt'])
    expect(metadata.id_token_signing_alg_values_supported).toEqual(['ES256'])
    expect(metadata.dpop_signing_alg_values_supported).toEqual(['PS256', 'ES256', 'EdDSA'])
  })
})
