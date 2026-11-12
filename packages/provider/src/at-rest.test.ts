import { beforeEach, describe, expect, test } from 'bun:test'
import { memoryAdapter } from '@oidcraft/adapter/memory'
import { randomString, sha256 } from '@oidcraft/core'
import { base64url, decodeJwt, generateKeyPair, SignJWT } from 'jose'
import type { Adapter, ArtifactKind, Client } from './index'
import { createProvider, type Provider } from './provider'
import { SESSION_COOKIE } from './session/session'

const ISSUER = 'https://op.example.com'
const REDIRECT = 'https://rp.example.com/cb'
const SECRET = 'a-long-enough-client-secret'
const FORM = { 'content-type': 'application/x-www-form-urlencoded' }

const client = (over: Partial<Client> = {}): Client => ({
  clientId: 'rp',
  clientSecret: SECRET,
  redirectUris: [REDIRECT],
  grantTypes: ['authorization_code', 'refresh_token', 'urn:ietf:params:oauth:grant-type:device_code'],
  responseTypes: ['code'],
  scopes: ['openid', 'profile', 'offline_access'],
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
let verifier: string
let challenge: string

const basic = `Basic ${btoa(`rp:${SECRET}`)}`
const hashOf = async (value: string) => base64url.encode(await sha256(value))

beforeEach(async () => {
  adapter = await memoryAdapter({ accounts })
  verifier = randomString() + randomString()
  challenge = base64url.encode(await sha256(verifier))
})

const build = (over: Record<string, unknown> = {}) =>
  createProvider({ issuer: ISSUER, adapter, interactionUrl: `${ISSUER}/interaction`, ...over } as Parameters<typeof createProvider>[0])

const post = (provider: Provider, path: string, body: Record<string, string>, headers: Record<string, string> = { authorization: basic }) =>
  provider.handle(
    new Request(`${ISSUER}${path}`, { method: 'POST', headers: { ...FORM, ...headers }, body: new URLSearchParams(body).toString() })
  )

const codeFor = async (provider: Provider) => {
  const params = new URLSearchParams({
    client_id: 'rp',
    redirect_uri: REDIRECT,
    response_type: 'code',
    scope: 'openid profile offline_access',
    code_challenge: challenge,
    code_challenge_method: 'S256'
  })
  let cookie = ''
  let response = await provider.handle(new Request(`${ISSUER}/authorize?${params}`))
  const interactions: string[] = []
  for (let leg = 0; leg < 4; leg++) {
    const location = new URL(response.headers.get('location') as string)
    if (!location.pathname.startsWith('/interaction/')) return { code: location.searchParams.get('code') as string, interactions, cookie }
    const id = location.pathname.split('/').pop() as string
    interactions.push(id)
    const view = await provider.interactions.find(id)
    const done = await provider.interactions.complete(
      id,
      view.kind === 'login' ? { login: { accountId: 'ada', acr: 'pwd' } } : { consent: { scopes: view.scopes } }
    )
    if (done.setCookie) cookie = `${SESSION_COOKIE}=${done.setCookie.split('=')[1]?.split(';')[0]}`
    response = await provider.handle(new Request(done.redirectTo, { headers: cookie ? { cookie } : {} }))
  }
  throw new Error('never reached the redirect')
}

const tokensFor = async (provider: Provider) => {
  const { code, cookie } = await codeFor(provider)
  const response = await post(provider, '/token', {
    grant_type: 'authorization_code',
    code,
    redirect_uri: REDIRECT,
    code_verifier: verifier
  })
  return { ...(await response.json()), cookie }
}

/** What a copy of the database holds: the record is there, and not under the value that redeems it. */
const expectHashed = async (kind: ArtifactKind, value: string) => {
  expect(await adapter.artifacts.find(kind, value)).toBeUndefined()
  expect(await adapter.artifacts.find(kind, await hashOf(value))).toBeDefined()
}

describe('NFR-S11: no bearer credential is stored as itself', () => {
  test('an authorization code', async () => {
    await adapter.clients.upsert?.(client())
    const { code } = await codeFor(build())
    await expectHashed('authorization_code', code)
  })

  test('an access token and a refresh token, and both still work', async () => {
    await adapter.clients.upsert?.(client())
    const provider = build()
    const issued = await tokensFor(provider)
    await expectHashed('access_token', issued.access_token)
    await expectHashed('refresh_token', issued.refresh_token)

    const userinfo = await provider.handle(
      new Request(`${ISSUER}/userinfo`, { headers: { authorization: `Bearer ${issued.access_token}` } })
    )
    expect(userinfo.status).toBe(200)
    const refreshed = await post(provider, '/token', { grant_type: 'refresh_token', refresh_token: issued.refresh_token })
    expect(refreshed.status).toBe(200)
  })

  test('the stored id redeems nothing', async () => {
    await adapter.clients.upsert?.(client())
    const provider = build()
    const issued = await tokensFor(provider)
    const stolen = await hashOf(issued.access_token)
    const userinfo = await provider.handle(new Request(`${ISSUER}/userinfo`, { headers: { authorization: `Bearer ${stolen}` } }))
    expect(userinfo.status).toBe(401)
    const refreshed = await post(provider, '/token', { grant_type: 'refresh_token', refresh_token: await hashOf(issued.refresh_token) })
    expect(refreshed.status).toBe(400)
  })

  test('a pushed request reference', async () => {
    await adapter.clients.upsert?.(client())
    const provider = build({ features: { pushedAuthorizationRequests: true } })
    const pushed = await post(provider, '/request', {
      client_id: 'rp',
      redirect_uri: REDIRECT,
      response_type: 'code',
      scope: 'openid',
      code_challenge: challenge,
      code_challenge_method: 'S256'
    })
    const { request_uri } = await pushed.json()
    await expectHashed('pushed_authorization_request', request_uri.split(':').pop())
  })

  test('a device code, which a person can still approve by its user code', async () => {
    await adapter.clients.upsert?.(client())
    const provider = build({ features: { deviceFlow: true } })
    const started = await (await post(provider, '/device/authorize', { scope: 'openid profile' })).json()
    await expectHashed('device_code', started.device_code)

    const { cookie } = await tokensFor(provider)
    const session = await provider.session(new Request(ISSUER, { headers: { cookie } }))
    const outcome = await provider.device.resolve(started.user_code, {
      accountId: 'ada',
      sessionId: session?.id as string,
      scopes: ['openid', 'profile']
    })
    expect(outcome.approved).toBe(true)
    expect((await provider.device.find(started.user_code))?.payload.status).toBe('approved')

    const redeemed = await post(provider, '/token', {
      grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
      device_code: started.device_code
    })
    expect(redeemed.status).toBe(200)
  })

  test('a registration access token, which still reads and is echoed back', async () => {
    const provider = build({ features: { dynamicRegistration: true } })
    const registered = await provider.handle(
      new Request(`${ISSUER}/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ redirect_uris: [REDIRECT] })
      })
    )
    const created = await registered.json()
    const stored = await adapter.clients.find(created.client_id)
    expect(stored?.registrationAccessToken).toBe(await hashOf(created.registration_access_token))

    const read = (token: string) =>
      provider.handle(new Request(`${ISSUER}/register?client_id=${created.client_id}`, { headers: { authorization: `Bearer ${token}` } }))
    const answer = await read(created.registration_access_token)
    expect(answer.status).toBe(200)
    expect((await answer.json()).registration_access_token).toBe(created.registration_access_token)
    expect((await read(stored?.registrationAccessToken as string)).status).toBe(401)
  })
})

describe('FR-T2: a jti is an identifier, never a credential', () => {
  const jwtTokens = async (provider: Provider) => {
    await adapter.clients.upsert?.(client({ accessTokenFormat: 'jwt' }))
    return tokensFor(provider)
  }
  const userinfo = (provider: Provider, token: string) =>
    provider.handle(new Request(`${ISSUER}/userinfo`, { headers: { authorization: `Bearer ${token}` } }))

  test('the JWT itself is accepted', async () => {
    const provider = build()
    const issued = await jwtTokens(provider)
    expect((await userinfo(provider, issued.access_token)).status).toBe(200)
  })

  test('its jti alone finds nothing', async () => {
    const provider = build()
    const issued = await jwtTokens(provider)
    expect((await userinfo(provider, decodeJwt(issued.access_token).jti as string)).status).toBe(401)
  })

  test('a JWT carrying a real jti under another key finds nothing', async () => {
    const provider = build()
    const issued = await jwtTokens(provider)
    const forged = await new SignJWT({ jti: decodeJwt(issued.access_token).jti as string })
      .setProtectedHeader({ alg: 'ES256', typ: 'at+jwt' })
      .setIssuer(ISSUER)
      .setExpirationTime('5m')
      .sign((await generateKeyPair('ES256', { extractable: true })).privateKey)
    expect((await userinfo(provider, forged)).status).toBe(401)
  })
})
