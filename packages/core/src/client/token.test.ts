import { beforeEach, describe, expect, it } from 'bun:test'
import { type AuthorizationCodePKCEConfig, OAuthStatus, OAuthType } from '../types'
import type { OAuth } from './module'
import { createOAuth, flush, installStorage, mockOAuthFunctions, registerOAuthCleanup } from './test-utils'
import { isExpiredToken } from './token'

const local = installStorage()
registerOAuthCleanup()

describe('checkToken', () => {
  let oauth: OAuth
  let refresh: ReturnType<typeof mockOAuthFunctions>['refresh']

  beforeEach(() => {
    local.clear()
    const functions = mockOAuthFunctions()
    refresh = functions.refresh
    oauth = createOAuth({
      config: { tokenPath: '/t', clientId: 'c' },
      functions
    })
  })

  it('refreshes an expired token and keeps the refresh_token', async () => {
    refresh.mockResolvedValue({ access_token: 'fresh', expires_in: 60 })
    oauth.setToken({ refresh_token: 'keep', access_token: 'stale', expires: Date.now() - 10_000 })

    await oauth.checkToken()

    expect(refresh).toHaveBeenCalled()
    expect(oauth.token().access_token).toBe('fresh')
    expect(oauth.token().refresh_token).toBe('keep')
    expect(oauth.token().expires).toBeGreaterThan(Date.now())
  })

  it('persists the RFC 6749 error body when the refresh token is rejected (invalid_grant)', async () => {
    refresh.mockResolvedValue({
      error: 'invalid_grant',
      error_description: 'Invalid refresh token',
      type: OAuthType.AUTHORIZATION_CODE
    })
    oauth.setToken({ refresh_token: 'dead', access_token: 'stale', token_type: 'Bearer', expires: Date.now() - 10_000 })

    await oauth.checkToken()

    expect(oauth.token()).toEqual({
      error: 'invalid_grant',
      error_description: 'Invalid refresh token',
      type: OAuthType.AUTHORIZATION_CODE
    })
    expect(oauth.status()).toBe(OAuthStatus.DENIED)
  })

  it('keeps the old token when refresh yields neither a fresh token nor an error (transient failure)', async () => {
    refresh.mockResolvedValue(undefined)
    const stale = { refresh_token: 'keep', access_token: 'stale', expires: Date.now() - 10_000 }
    oauth.setToken(stale)

    await oauth.checkToken()

    expect(oauth.token()).toEqual(stale)
  })

  it('does not refresh a token that is not expired', async () => {
    oauth.setToken({ access_token: 'live', expires: Date.now() + 60_000 })

    await oauth.checkToken()

    expect(refresh).not.toHaveBeenCalled()
  })

  it('derives expires from expires_in on a token that has none', async () => {
    oauth.setToken({ access_token: 'live', expires_in: 60 })

    await oauth.checkToken()

    expect(oauth.token().expires).toBeGreaterThan(Date.now())
  })

  it('deduplicates concurrent calls', async () => {
    refresh.mockResolvedValue({ access_token: 'fresh', expires_in: 60 })
    oauth.setToken({ refresh_token: 'r', access_token: 'stale', expires: Date.now() - 10_000 })

    await Promise.all([oauth.checkToken(), oauth.checkToken(), oauth.checkToken()])

    expect(refresh).toHaveBeenCalledTimes(1)
  })

  it('refreshes a stored token that is already expired at startup', async () => {
    // the watch source is the raw access_token, not the derived (expiry-aware) accessToken — which is
    // undefined here, i.e. exactly the case that has to trigger a refresh
    local.setItem('token', JSON.stringify({ refresh_token: 'r', access_token: 'stale', token_type: 'Bearer', expires: Date.now() - 1 }))
    const functions = mockOAuthFunctions()
    functions.refresh.mockResolvedValue({ access_token: 'fresh', token_type: 'Bearer', expires_in: 60 })

    const restored = createOAuth({ config: { tokenPath: '/t', clientId: 'c' }, functions })
    await flush()

    expect(functions.refresh).toHaveBeenCalled()
    expect(restored.accessToken()).toBe('Bearer fresh')
  })

  it('isolates token state between instances', () => {
    oauth.setToken({ access_token: 'first' })
    const second = createOAuth({ storageKey: 'other', functions: mockOAuthFunctions() })

    expect(second.token()).toEqual({})
    expect(oauth.token().access_token).toBe('first')
  })
})

describe('autoconfigOauth', () => {
  beforeEach(() => {
    local.clear()
  })

  it('maps the discovery document onto the config', async () => {
    const functions = mockOAuthFunctions()
    functions.openIdConfiguration.mockResolvedValue({
      authorization_endpoint: '/auth',
      token_endpoint: '/token',
      revocation_endpoint: '/revoke',
      userinfo_endpoint: '/userinfo',
      introspection_endpoint: '/introspect',
      end_session_endpoint: '/logout',
      jwks_uri: '/jwks',
      code_challenge_methods_supported: ['S256']
    })
    const oauth = createOAuth({ config: { issuerPath: 'https://idp' } as any, functions })

    await oauth.autoconfigOauth()

    expect(oauth.config()).toMatchObject({
      authorizePath: '/auth',
      tokenPath: '/token',
      revokePath: '/revoke',
      userPath: '/userinfo',
      introspectionPath: '/introspect',
      logoutPath: '/logout',
      jwksUri: '/jwks',
      pkce: true,
      scope: 'openid'
    })
  })

  it('skips discovery when the endpoints are already configured', async () => {
    const functions = mockOAuthFunctions()
    const oauth = createOAuth({ config: { tokenPath: '/t', clientId: 'c' }, functions })

    await oauth.autoconfigOauth()

    expect(functions.openIdConfiguration).not.toHaveBeenCalled()
  })

  it('leaves an explicit pkce setting alone', async () => {
    const functions = mockOAuthFunctions()
    functions.openIdConfiguration.mockResolvedValue({ token_endpoint: '/token', code_challenge_methods_supported: ['S256'] })
    const oauth = createOAuth({ config: { issuerPath: 'https://idp', pkce: false } as any, functions })

    await oauth.autoconfigOauth()

    expect((oauth.config() as AuthorizationCodePKCEConfig)?.pkce).toBe(false)
  })
})

describe('token accessors', () => {
  beforeEach(() => {
    local.clear()
  })

  it('accessToken needs both token_type and access_token', () => {
    const oauth = createOAuth({ functions: mockOAuthFunctions() })

    oauth.setToken({ access_token: 'at' })
    expect(oauth.accessToken()).toBeUndefined()

    oauth.setToken({ access_token: 'at', token_type: 'Bearer' })
    expect(oauth.accessToken()).toBe('Bearer at')
  })

  it('accessToken goes undefined once the token expires', () => {
    const oauth = createOAuth({ functions: mockOAuthFunctions() })

    oauth.setToken({ access_token: 'at', token_type: 'Bearer', expires: Date.now() + 60_000 })
    expect(oauth.accessToken()).toBe('Bearer at')

    // handing out a dead bearer guarantees a 401, which the fetch layer then stores as the IdP's error —
    // a session that could not be refreshed should send nothing rather than something known-broken
    oauth.setToken({ access_token: 'at', token_type: 'Bearer', expires: Date.now() - 1 })
    expect(oauth.accessToken()).toBeUndefined()
  })

  it('status reflects error, expiry and presence', () => {
    const oauth = createOAuth({ functions: mockOAuthFunctions() })

    expect(oauth.status()).toBe(OAuthStatus.NOT_AUTHORIZED)

    oauth.setToken({ access_token: 'at', expires: Date.now() + 60_000 })
    expect(oauth.status()).toBe(OAuthStatus.AUTHORIZED)
    expect(oauth.isAuthorized()).toBe(true)

    oauth.setToken({ access_token: 'at', expires: Date.now() - 1 })
    expect(oauth.status()).toBe(OAuthStatus.NOT_AUTHORIZED)

    oauth.setToken({ error: 'nope', error_description: 'because' })
    expect(oauth.status()).toBe(OAuthStatus.DENIED)
    expect(oauth.hasError()).toBe(true)
    expect(oauth.error()).toBe('nope')
    expect(oauth.errorDescription()).toBe('because')
  })

  it('type mirrors the grant that produced the token', () => {
    const oauth = createOAuth({ functions: mockOAuthFunctions() })
    oauth.setToken({ access_token: 'at', type: OAuthType.RESOURCE })
    expect(oauth.type()).toBe(OAuthType.RESOURCE)
  })
})

describe('cross-tab', () => {
  beforeEach(() => {
    local.clear()
  })

  it('signs out when another tab logs out', () => {
    local.setItem('token', JSON.stringify({ access_token: 'at', token_type: 'Bearer', expires: Date.now() + 60_000 }))
    const oauth = createOAuth({ config: { tokenPath: '/t', clientId: 'c' }, functions: mockOAuthFunctions() })
    expect(oauth.isAuthorized()).toBe(true)

    // what logout() in another tab leaves behind, plus the event the browser fires here
    local.setItem('token', JSON.stringify({}))
    globalThis.dispatchEvent(new StorageEvent('storage', { key: 'token' }))

    expect(oauth.token()).toEqual({})
    expect(oauth.isAuthorized()).toBe(false)
  })

  it("adopts another tab's refreshed token", () => {
    local.setItem('token', JSON.stringify({ access_token: 'old', token_type: 'Bearer', expires: Date.now() + 60_000 }))
    const oauth = createOAuth({ config: { tokenPath: '/t', clientId: 'c' }, functions: mockOAuthFunctions() })

    local.setItem('token', JSON.stringify({ access_token: 'new', token_type: 'Bearer', expires: Date.now() + 60_000 }))
    globalThis.dispatchEvent(new StorageEvent('storage', { key: 'token' }))

    expect(oauth.accessToken()).toBe('Bearer new')
  })

  it('stops listening once disposed', () => {
    const oauth = createOAuth({ functions: mockOAuthFunctions() })
    oauth.dispose()

    local.setItem('token', JSON.stringify({ access_token: 'at', token_type: 'Bearer' }))
    globalThis.dispatchEvent(new StorageEvent('storage', { key: 'token' }))

    expect(oauth.token()).toEqual({})
  })
})

describe('isExpiredToken', () => {
  it('is false without an expires field', () => {
    expect(isExpiredToken({ access_token: 'at' })).toBe(false)
    expect(isExpiredToken(undefined)).toBe(false)
  })

  it('is true once expires is in the past', () => {
    expect(isExpiredToken({ expires: Date.now() - 1 })).toBe(true)
    expect(isExpiredToken({ expires: Date.now() + 60_000 })).toBe(false)
  })
})
