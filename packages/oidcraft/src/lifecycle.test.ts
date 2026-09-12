import { beforeEach, describe, expect, test } from 'bun:test'
import { decodeJwt } from 'jose'
import { memoryAdapter } from './adapters/memory'
import type { Adapter, Client, LogoutNotification } from './index'
import { createProvider, type Provider } from './provider'
import { base64url, sha256, token } from './random'
import { SESSION_COOKIE } from './session'

const ISSUER = 'https://op.example.com'
const REDIRECT = 'https://rp.example.com/cb'
const SECRET = 'shhh-a-long-enough-secret'

const client = (over: Partial<Client> = {}): Client => ({
  clientId: 'rp',
  clientSecret: SECRET,
  redirectUris: [REDIRECT],
  postLogoutRedirectUris: ['https://rp.example.com/bye'],
  grantTypes: ['authorization_code', 'refresh_token'],
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
let provider: Provider
let delivered: LogoutNotification[]
let verifier: string
let challenge: string

const basic = (id = 'rp', secret = SECRET) => `Basic ${btoa(`${id}:${secret}`)}`

beforeEach(async () => {
  delivered = []
  adapter = await memoryAdapter({ accounts })
  await adapter.clients.create?.(client())
  await adapter.clients.create?.(client({ clientId: 'other', clientSecret: SECRET }))
  provider = createProvider({
    issuer: ISSUER,
    adapter,
    interactionUrl: `${ISSUER}/interaction`,
    onLogout: notifications => {
      delivered = notifications
    }
  })
  verifier = token(32) + token(32)
  challenge = base64url(await sha256(verifier))
})

const post = (path: string, body: Record<string, string>, headers: Record<string, string> = {}) =>
  provider.handle(
    new Request(`${ISSUER}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers },
      body: new URLSearchParams(body).toString()
    })
  )

const tokens = async () => {
  const params = new URLSearchParams({
    client_id: 'rp',
    redirect_uri: REDIRECT,
    response_type: 'code',
    scope: 'openid profile offline_access',
    code_challenge: challenge,
    code_challenge_method: 'S256'
  })
  const first = await provider.handle(new Request(`${ISSUER}/authorize?${params}`))
  const loginId = new URL(first.headers.get('location') as string).pathname.split('/').pop() as string
  const login = await provider.interactions.complete(loginId, { login: { accountId: 'ada' } })
  const cookie = `${SESSION_COOKIE}=${(login.setCookie as string).split('=')[1]?.split(';')[0]}`

  const second = await provider.handle(new Request(login.redirectTo, { headers: { cookie } }))
  const consentId = new URL(second.headers.get('location') as string).pathname.split('/').pop() as string
  const consent = await provider.interactions.complete(consentId, { consent: { scopes: ['openid', 'profile', 'offline_access'] } })

  const third = await provider.handle(new Request(consent.redirectTo, { headers: { cookie } }))
  const code = new URL(third.headers.get('location') as string).searchParams.get('code') as string
  const body = await (
    await post(
      '/token',
      { grant_type: 'authorization_code', code, redirect_uri: REDIRECT, code_verifier: verifier },
      { authorization: basic() }
    )
  ).json()
  return { ...body, cookie }
}

describe('revocation', () => {
  test('revoking a refresh token takes the whole grant with it', async () => {
    const issued = await tokens()
    const response = await post('/revoke', { token: issued.refresh_token }, { authorization: basic() })
    expect(response.status).toBe(200)

    const userinfo = await provider.handle(
      new Request(`${ISSUER}/userinfo`, { headers: { authorization: `Bearer ${issued.access_token}` } })
    )
    expect(userinfo.status).toBe(401)
    const refresh = await post('/token', { grant_type: 'refresh_token', refresh_token: issued.refresh_token }, { authorization: basic() })
    expect((await refresh.json()).error).toBe('invalid_grant')
  })

  test('revoking an access token leaves the refresh token usable', async () => {
    const issued = await tokens()
    await post('/revoke', { token: issued.access_token, token_type_hint: 'access_token' }, { authorization: basic() })
    const userinfo = await provider.handle(
      new Request(`${ISSUER}/userinfo`, { headers: { authorization: `Bearer ${issued.access_token}` } })
    )
    expect(userinfo.status).toBe(401)
    const refresh = await post('/token', { grant_type: 'refresh_token', refresh_token: issued.refresh_token }, { authorization: basic() })
    expect(refresh.status).toBe(200)
  })

  // RFC 7009 §2.2: anything but 200 makes this an oracle for which tokens exist.
  test('an unknown token is still a 200', async () => {
    expect((await post('/revoke', { token: 'never-existed' }, { authorization: basic() })).status).toBe(200)
  })

  test("another client's token is a 200 and is not revoked", async () => {
    const issued = await tokens()
    const response = await post('/revoke', { token: issued.refresh_token }, { authorization: basic('other') })
    expect(response.status).toBe(200)
    const refresh = await post('/token', { grant_type: 'refresh_token', refresh_token: issued.refresh_token }, { authorization: basic() })
    expect(refresh.status).toBe(200)
  })

  test('an unauthenticated caller is rejected', async () => {
    expect((await post('/revoke', { token: 'x' })).status).toBe(401)
  })
})

describe('introspection', () => {
  test('describes a live access token', async () => {
    const issued = await tokens()
    const body = await (await post('/introspect', { token: issued.access_token }, { authorization: basic() })).json()
    expect(body.active).toBe(true)
    expect(body.client_id).toBe('rp')
    expect(body.sub).toBe('ada')
    expect(body.scope).toContain('openid')
    expect(body.iss).toBe(ISSUER)
  })

  test('an unknown token is active:false, not an error', async () => {
    const response = await post('/introspect', { token: 'nope' }, { authorization: basic() })
    expect(response.status).toBe(200)
    expect((await response.json()).active).toBe(false)
  })

  // RFC 7662 §2.2: the difference between "expired" and "someone else's" must not leak.
  test("another client's token is indistinguishable from an unknown one", async () => {
    const issued = await tokens()
    const mine = await (await post('/introspect', { token: issued.access_token }, { authorization: basic('other') })).json()
    const unknown = await (await post('/introspect', { token: 'nope' }, { authorization: basic('other') })).json()
    expect(mine).toEqual(unknown)
  })

  test('a revoked token reads as inactive', async () => {
    const issued = await tokens()
    await post('/revoke', { token: issued.refresh_token }, { authorization: basic() })
    expect((await (await post('/introspect', { token: issued.access_token }, { authorization: basic() })).json()).active).toBe(false)
  })

  test('an unauthenticated caller is rejected', async () => {
    expect((await post('/introspect', { token: 'x' })).status).toBe(401)
  })
})

describe('end session', () => {
  test('ends the session and clears the cookie', async () => {
    const issued = await tokens()
    const response = await provider.handle(new Request(`${ISSUER}/session/end`, { headers: { cookie: issued.cookie } }))
    expect(response.status).toBe(200)
    expect(response.headers.get('set-cookie')).toContain('Max-Age=0')

    const params = new URLSearchParams({
      client_id: 'rp',
      redirect_uri: REDIRECT,
      response_type: 'code',
      scope: 'openid',
      prompt: 'none',
      code_challenge: challenge,
      code_challenge_method: 'S256'
    })
    const after = await provider.handle(new Request(`${ISSUER}/authorize?${params}`, { headers: { cookie: issued.cookie } }))
    expect(new URL(after.headers.get('location') as string).searchParams.get('error')).toBe('login_required')
  })

  test('redirects to a registered post_logout_redirect_uri with the state', async () => {
    const issued = await tokens()
    const url = `${ISSUER}/session/end?id_token_hint=${issued.id_token}&post_logout_redirect_uri=https%3A%2F%2Frp.example.com%2Fbye&state=s1`
    const response = await provider.handle(new Request(url, { headers: { cookie: issued.cookie } }))
    expect(response.status).toBe(303)
    const location = new URL(response.headers.get('location') as string)
    expect(location.origin + location.pathname).toBe('https://rp.example.com/bye')
    expect(location.searchParams.get('state')).toBe('s1')
  })

  test('an unregistered post_logout_redirect_uri is refused', async () => {
    const issued = await tokens()
    const url = `${ISSUER}/session/end?id_token_hint=${issued.id_token}&post_logout_redirect_uri=https%3A%2F%2Fevil.example.net%2F`
    const response = await provider.handle(new Request(url, { headers: { cookie: issued.cookie } }))
    expect(response.status).toBe(400)
  })

  // Without verification, anyone could name a client and be redirected to its registered URI.
  test('a post_logout_redirect_uri without a verified id_token_hint is refused', async () => {
    const response = await provider.handle(
      new Request(`${ISSUER}/session/end?client_id=rp&post_logout_redirect_uri=https%3A%2F%2Frp.example.com%2Fbye`)
    )
    expect(response.status).toBe(400)
  })

  test('a forged id_token_hint is refused', async () => {
    const forged = `${btoa(JSON.stringify({ alg: 'none' }))}.${btoa(JSON.stringify({ aud: 'rp', iss: ISSUER }))}.`
    const response = await provider.handle(new Request(`${ISSUER}/session/end?id_token_hint=${forged}`))
    expect(response.status).toBe(400)
  })

  // FR-C11 / FR-A1: the core mints the tokens; the host delivers them.
  test('hands back-channel logout tokens to the host instead of posting them', async () => {
    await adapter.clients.update?.('rp', { backchannelLogoutUri: 'https://rp.example.com/backchannel' })
    const issued = await tokens()
    await provider.handle(new Request(`${ISSUER}/session/end`, { headers: { cookie: issued.cookie } }))

    expect(delivered).toHaveLength(1)
    expect(delivered[0]?.uri).toBe('https://rp.example.com/backchannel')
    const claims = decodeJwt(delivered[0]?.logoutToken as string)
    expect(claims.iss).toBe(ISSUER)
    expect(claims.aud).toBe('rp')
    expect(claims.sub).toBe('ada')
    expect(Object.keys(claims.events as object)).toEqual(['http://schemas.openid.net/event/backchannel-logout'])
    expect(claims.nonce).toBeUndefined()
  })

  test('no session is still a clean sign-out', async () => {
    const response = await provider.handle(new Request(`${ISSUER}/session/end`))
    expect(response.status).toBe(200)
    expect(delivered).toHaveLength(0)
  })
})
