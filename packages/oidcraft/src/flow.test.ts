import { beforeEach, describe, expect, test } from 'bun:test'
import { createLocalJWKSet, jwtVerify } from 'jose'
import { memoryAdapter } from './adapters/memory'
import type { Adapter, Client } from './index'
import { createProvider, type Provider } from './provider'
import { base64url, sha256, token } from './random'
import { SESSION_COOKIE } from './session'

const ISSUER = 'https://op.example.com'
const REDIRECT = 'https://rp.example.com/cb'

const client = (over: Partial<Client> = {}): Client => ({
  clientId: 'rp',
  clientSecret: 'shhh-a-long-enough-secret',
  redirectUris: [REDIRECT],
  grantTypes: ['authorization_code', 'refresh_token'],
  responseTypes: ['code'],
  scopes: ['openid', 'profile', 'email', 'offline_access'],
  tokenEndpointAuthMethod: 'client_secret_basic',
  createdAt: new Date(),
  updatedAt: new Date(),
  ...over
})

const accounts = {
  async find(accountId: string) {
    return { accountId, claims: {} }
  },
  async claims(_accountId: string, scopes: string[]) {
    return scopes.includes('profile') ? { name: 'Ada Lovelace', email: 'ada@example.com' } : {}
  }
}

let adapter: Adapter
let provider: Provider
let verifier: string
let challenge: string

beforeEach(async () => {
  adapter = await memoryAdapter({ accounts })
  await adapter.clients.create?.(client())
  provider = createProvider({ issuer: ISSUER, adapter, interactionUrl: `${ISSUER}/interaction` })
  verifier = token(32) + token(32)
  challenge = base64url(await sha256(verifier))
})

const authorizeUrl = (over: Record<string, string> = {}) => {
  const params = new URLSearchParams({
    client_id: 'rp',
    redirect_uri: REDIRECT,
    response_type: 'code',
    scope: 'openid profile offline_access',
    state: 'xyz',
    nonce: 'n-0S6_WzA2Mj',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    ...over
  })
  return `${ISSUER}/authorize?${params}`
}

const go = (url: string, cookie?: string) => provider.handle(new Request(url, { headers: cookie ? { cookie } : {} }))

const basic = (id = 'rp', secret = 'shhh-a-long-enough-secret') => `Basic ${btoa(`${id}:${secret}`)}`

const post = (path: string, body: Record<string, string>, headers: Record<string, string> = {}) =>
  provider.handle(
    new Request(`${ISSUER}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers },
      body: new URLSearchParams(body).toString()
    })
  )

/** Drives the browser legs a real user would: authorize -> login -> consent -> code. */
const loginAndConsent = async (over: Record<string, string> = {}) => {
  const first = await go(authorizeUrl(over))
  const loginId = new URL(first.headers.get('location') as string).pathname.split('/').pop() as string

  const login = await provider.interactions.complete(loginId, { login: { accountId: 'ada' } })
  const cookie = `${SESSION_COOKIE}=${(login.setCookie as string).split('=')[1]?.split(';')[0]}`

  const second = await go(login.redirectTo, cookie)
  const consentId = new URL(second.headers.get('location') as string).pathname.split('/').pop() as string

  const consent = await provider.interactions.complete(consentId, { consent: { scopes: ['openid', 'profile', 'offline_access'] } })
  const third = await go(consent.redirectTo, cookie)
  return { location: new URL(third.headers.get('location') as string), cookie }
}

describe('authorization endpoint', () => {
  test('an unknown client is reported directly, never redirected', async () => {
    const response = await go(authorizeUrl({ client_id: 'ghost' }))
    expect(response.status).toBe(400)
    expect((await response.json()).error).toBe('invalid_request')
  })

  // NFR-S2 / RFC 9700 §4.1: redirecting to an unregistered URI is an open redirector.
  test('an unregistered redirect_uri is reported directly, never redirected', async () => {
    const response = await go(authorizeUrl({ redirect_uri: 'https://evil.example.net/cb' }))
    expect(response.status).toBe(400)
    expect(response.headers.get('location')).toBeNull()
    expect((await response.json()).error_description).toContain('not registered')
  })

  test('an exact-match redirect_uri is required, not a prefix', async () => {
    const response = await go(authorizeUrl({ redirect_uri: `${REDIRECT}/deeper` }))
    expect(response.status).toBe(400)
  })

  // FR-C3: mandatory for every client.
  test('a missing code_challenge is refused', async () => {
    const url = new URL(authorizeUrl())
    url.searchParams.delete('code_challenge')
    const response = await go(url.toString())
    expect(new URL(response.headers.get('location') as string).searchParams.get('error')).toBe('invalid_request')
  })

  test('code_challenge_method=plain is refused', async () => {
    const response = await go(authorizeUrl({ code_challenge_method: 'plain' }))
    const error = new URL(response.headers.get('location') as string).searchParams
    expect(error.get('error')).toBe('invalid_request')
    expect(error.get('error_description')).toContain('S256')
  })

  test('an unsupported response_type redirects with the error and the state', async () => {
    const response = await go(authorizeUrl({ response_type: 'token' }))
    const params = new URL(response.headers.get('location') as string).searchParams
    expect(params.get('error')).toBe('unsupported_response_type')
    expect(params.get('state')).toBe('xyz')
  })

  test('a scope without openid is refused', async () => {
    const response = await go(authorizeUrl({ scope: 'profile' }))
    expect(new URL(response.headers.get('location') as string).searchParams.get('error')).toBe('invalid_scope')
  })

  test('with no session it suspends into a login interaction', async () => {
    const response = await go(authorizeUrl())
    expect(response.status).toBe(303)
    expect(response.headers.get('location')).toContain(`${ISSUER}/interaction/`)
  })

  // OIDC Core §3.1.2.6
  test('prompt=none with no session is login_required, not an interaction', async () => {
    const response = await go(authorizeUrl({ prompt: 'none' }))
    const params = new URL(response.headers.get('location') as string).searchParams
    expect(params.get('error')).toBe('login_required')
    expect(params.get('iss')).toBe(ISSUER)
  })

  test('prompt=none with a session but no grant is consent_required', async () => {
    const first = await go(authorizeUrl())
    const id = new URL(first.headers.get('location') as string).pathname.split('/').pop() as string
    const login = await provider.interactions.complete(id, { login: { accountId: 'ada' } })
    const cookie = `${SESSION_COOKIE}=${(login.setCookie as string).split('=')[1]?.split(';')[0]}`
    const response = await go(authorizeUrl({ prompt: 'none' }), cookie)
    expect(new URL(response.headers.get('location') as string).searchParams.get('error')).toBe('consent_required')
  })

  test('a completed login and consent yields a code, the state and the issuer', async () => {
    const { location } = await loginAndConsent()
    expect(location.origin + location.pathname).toBe(REDIRECT)
    expect(location.searchParams.get('code')).toBeTruthy()
    expect(location.searchParams.get('state')).toBe('xyz')
    // FR-C14
    expect(location.searchParams.get('iss')).toBe(ISSUER)
  })

  // FR-I4: the second visit is silent.
  test('a remembered grant skips consent on the next authorization', async () => {
    const { cookie } = await loginAndConsent()
    const again = await go(authorizeUrl(), cookie)
    const location = new URL(again.headers.get('location') as string)
    expect(location.searchParams.get('code')).toBeTruthy()
  })
})

describe('token endpoint', () => {
  const exchange = async (code: string, over: Record<string, string> = {}) =>
    post(
      '/token',
      { grant_type: 'authorization_code', code, redirect_uri: REDIRECT, code_verifier: verifier, ...over },
      {
        authorization: basic()
      }
    )

  test('exchanges a code for access, refresh and ID tokens', async () => {
    const { location } = await loginAndConsent()
    const response = await exchange(location.searchParams.get('code') as string)
    expect(response.status).toBe(200)
    const body = await response.json()
    expect(body.token_type).toBe('Bearer')
    expect(body.access_token).toBeTruthy()
    expect(body.refresh_token).toBeTruthy()
    expect(body.id_token).toBeTruthy()
    expect(response.headers.get('cache-control')).toBe('no-store')
  })

  test('the ID token verifies against the published JWKS and carries the nonce', async () => {
    const { location } = await loginAndConsent()
    const body = await (await exchange(location.searchParams.get('code') as string)).json()
    const jwks = await (await provider.handle(new Request(`${ISSUER}/jwks`))).json()
    const { payload } = await jwtVerify(body.id_token, createLocalJWKSet(jwks), { issuer: ISSUER, audience: 'rp' })
    expect(payload.sub).toBe('ada')
    expect(payload.nonce).toBe('n-0S6_WzA2Mj')
    expect(payload.at_hash).toBeTruthy()
    expect(payload.auth_time).toBeNumber()
  })

  test('a wrong code_verifier is refused', async () => {
    const { location } = await loginAndConsent()
    const response = await exchange(location.searchParams.get('code') as string, { code_verifier: token(32) + token(32) })
    expect(response.status).toBe(400)
    expect((await response.json()).error).toBe('invalid_grant')
  })

  test('a mismatched redirect_uri is refused', async () => {
    const { location } = await loginAndConsent()
    const response = await exchange(location.searchParams.get('code') as string, { redirect_uri: 'https://rp.example.com/other' })
    expect((await response.json()).error).toBe('invalid_grant')
  })

  // FR-T4 / RFC 9700 §4.14.2: the replay revokes everything the code produced.
  test('replaying an authorization code revokes the whole grant', async () => {
    const { location } = await loginAndConsent()
    const code = location.searchParams.get('code') as string
    const first = await (await exchange(code)).json()

    const replay = await exchange(code)
    expect(replay.status).toBe(400)
    expect((await replay.json()).error_description).toContain('revoked')

    const refresh = await post('/token', { grant_type: 'refresh_token', refresh_token: first.refresh_token }, { authorization: basic() })
    expect((await refresh.json()).error).toBe('invalid_grant')
  })

  // FR-T3: rotation is unconditional.
  test('a refresh rotates the token and replaying the old one revokes the grant', async () => {
    const { location } = await loginAndConsent()
    const first = await (await exchange(location.searchParams.get('code') as string)).json()

    const rotated = await (
      await post('/token', { grant_type: 'refresh_token', refresh_token: first.refresh_token }, { authorization: basic() })
    ).json()
    expect(rotated.refresh_token).toBeTruthy()
    expect(rotated.refresh_token).not.toBe(first.refresh_token)

    const replay = await post('/token', { grant_type: 'refresh_token', refresh_token: first.refresh_token }, { authorization: basic() })
    expect((await replay.json()).error).toBe('invalid_grant')

    const afterRevocation = await post(
      '/token',
      { grant_type: 'refresh_token', refresh_token: rotated.refresh_token },
      { authorization: basic() }
    )
    expect((await afterRevocation.json()).error).toBe('invalid_grant')
  })

  test('a refresh may narrow the scope but never widen it', async () => {
    const { location } = await loginAndConsent()
    const first = await (await exchange(location.searchParams.get('code') as string)).json()
    const widened = await post(
      '/token',
      { grant_type: 'refresh_token', refresh_token: first.refresh_token, scope: 'openid email' },
      { authorization: basic() }
    )
    expect((await widened.json()).error).toBe('invalid_scope')
  })

  test('a bad client secret is rejected', async () => {
    const { location } = await loginAndConsent()
    const response = await exchange(location.searchParams.get('code') as string, {})
    expect(response.status).toBe(200)
    const bad = await post(
      '/token',
      { grant_type: 'authorization_code', code: 'x', redirect_uri: REDIRECT, code_verifier: verifier },
      { authorization: basic('rp', 'wrong') }
    )
    expect(bad.status).toBe(401)
    expect((await bad.json()).error).toBe('invalid_client')
  })

  test('credentials in both the header and the body are refused rather than resolved', async () => {
    const response = await post(
      '/token',
      { grant_type: 'authorization_code', code: 'x', client_id: 'rp', client_secret: 'shhh-a-long-enough-secret' },
      { authorization: basic() }
    )
    expect(response.status).toBe(401)
    expect((await response.json()).error_description).toContain('both')
  })

  test('an unknown grant_type is refused', async () => {
    const response = await post('/token', { grant_type: 'password', username: 'a', password: 'b' }, { authorization: basic() })
    expect((await response.json()).error).toBe('unauthorized_client')
  })
})

describe('userinfo', () => {
  test('returns the claims the granted scopes release', async () => {
    const { location } = await loginAndConsent()
    const tokens = await (
      await post(
        '/token',
        {
          grant_type: 'authorization_code',
          code: location.searchParams.get('code') as string,
          redirect_uri: REDIRECT,
          code_verifier: verifier
        },
        { authorization: basic() }
      )
    ).json()

    const response = await provider.handle(
      new Request(`${ISSUER}/userinfo`, { headers: { authorization: `Bearer ${tokens.access_token}` } })
    )
    expect(response.status).toBe(200)
    const body = await response.json()
    expect(body.sub).toBe('ada')
    expect(body.name).toBe('Ada Lovelace')
  })

  test('an unknown token is 401 with a WWW-Authenticate challenge', async () => {
    const response = await provider.handle(new Request(`${ISSUER}/userinfo`, { headers: { authorization: 'Bearer nope' } }))
    expect(response.status).toBe(401)
    expect(response.headers.get('www-authenticate')).toContain('Bearer')
  })

  test('no token at all is 401', async () => {
    expect((await provider.handle(new Request(`${ISSUER}/userinfo`))).status).toBe(401)
  })
})

describe('interaction', () => {
  test('exposes what the screen needs and nothing secret', async () => {
    const first = await go(authorizeUrl())
    const id = new URL(first.headers.get('location') as string).pathname.split('/').pop() as string
    const view = await provider.interactions.find(id)
    expect(view.kind).toBe('login')
    expect(view.clientId).toBe('rp')
    expect(view.scopes).toContain('openid')
  })

  test('a denied interaction redirects to the client with access_denied', async () => {
    const first = await go(authorizeUrl())
    const id = new URL(first.headers.get('location') as string).pathname.split('/').pop() as string
    const { redirectTo } = await provider.interactions.complete(id, { error: { error: 'access_denied' } })
    const url = new URL(redirectTo)
    expect(url.origin + url.pathname).toBe(REDIRECT)
    expect(url.searchParams.get('error')).toBe('access_denied')
    expect(url.searchParams.get('state')).toBe('xyz')
  })

  test('an unknown interaction is a 404, not a crash', async () => {
    expect(provider.interactions.find('nope')).rejects.toThrow()
  })
})
