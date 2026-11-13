import { afterEach, beforeEach, describe, expect, it, jest, setSystemTime } from 'bun:test'
import { type AuthorizationCodePKCEConfig, OAuthStatus, type OAuthToken, OAuthType } from '@oidcraft/core'
import { createOAuth as create, type OAuth } from './module'
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

  // A request sent at the boundary would arrive with a token that has just lapsed.
  it('refreshes a token about to expire, not only one that has', async () => {
    refresh.mockResolvedValue({ access_token: 'fresh', expires_in: 3600 })
    oauth.setToken({ refresh_token: 'r', access_token: 'ending', expires_in: 3600, expires: Date.now() + 10_000 })

    await oauth.checkToken()

    expect(refresh).toHaveBeenCalledTimes(1)
    expect(oauth.token().access_token).toBe('fresh')
  })

  // FR-L5: expires_in is RECOMMENDED, not required (RFC 6749 §5.1); a provider that leaves it out still rotated.
  it('keeps a refresh response that says nothing of when it expires', async () => {
    refresh.mockResolvedValue({ access_token: 'fresh', refresh_token: 'r2' })
    oauth.setToken({ refresh_token: 'r', access_token: 'stale', id_token: 'id', expires: Date.now() - 10_000 })

    await oauth.checkToken()

    expect(oauth.token()).toMatchObject({ access_token: 'fresh', refresh_token: 'r2', id_token: 'id' })
  })

  // A token's liveness is read off the clock; without a write at expiry a binding keeps showing it signed in.
  it('tells its readers when the token lapses', () => {
    jest.useFakeTimers()
    const start = Date.now()
    try {
      oauth.setToken({ access_token: 'a', token_type: 'Bearer', expires: start + 5_000 })
      let notified = 0
      const off = oauth.tokenStore.subscribe(() => notified++)
      setSystemTime(start + 5_001)
      jest.advanceTimersByTime(5_001)
      off()
      expect(notified).toBeGreaterThan(0)
      expect(oauth.isAuthorized()).toBe(false)
    } finally {
      jest.useRealTimers()
      setSystemTime()
    }
  })

  // FR-L5: the lock is let go after 30 s, but the request is not: its rotated refresh token is the only live one left.
  it('keeps a rotated token that arrives after the refresh was given up on', async () => {
    jest.useFakeTimers()
    try {
      let answer: ((token: OAuthToken) => void) | undefined
      refresh.mockImplementation(() => new Promise(resolve => (answer = resolve)))
      oauth.setToken({ refresh_token: 'r', access_token: 'stale', expires: Date.now() - 10_000 })

      const checking = oauth.checkToken()
      for (let tick = 0; !answer && tick < 100; tick++) await Promise.resolve()
      jest.advanceTimersByTime(30_001)
      await checking
      answer?.({ access_token: 'late', refresh_token: 'r2', expires_in: 60 })
      for (let tick = 0; tick < 10; tick++) await Promise.resolve()

      expect(oauth.token()).toMatchObject({ access_token: 'late', refresh_token: 'r2' })
    } finally {
      jest.useRealTimers()
    }
  })

  // A rotated refresh token is the only live one: dropped, the next refresh would replay the spent one (FR-L5, FR-T4).
  it('stores a refresh answered after the storage key changed under the key it was asked for', async () => {
    refresh.mockImplementation(async () => {
      oauth.setStorageKey('tenant-b')
      return { access_token: 'fresh', refresh_token: 'r2', expires_in: 60 }
    })
    oauth.setToken({ refresh_token: 'r', access_token: 'stale', expires: Date.now() - 10_000 })

    await oauth.checkToken()

    expect(oauth.token().access_token).toBeUndefined()
    expect(globalThis.localStorage.getItem('tenant-b')).toBeNull()
    expect(JSON.parse(globalThis.localStorage.getItem('token') ?? '{}')).toMatchObject({ access_token: 'fresh', refresh_token: 'r2' })
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

// FR-L5: two tabs presenting one refresh token is a replay to a provider that rotates (FR-T3).
describe('checkToken across tabs', () => {
  const navigator = globalThis.navigator as Navigator & { locks?: LockManager }
  let held: Promise<unknown> = Promise.resolve()

  beforeEach(() => {
    local.clear()
    held = Promise.resolve()
    // One exclusive lock, as an origin's tabs share: each request waits for the one before it.
    const locks = {
      request: (_name: string, task: () => Promise<unknown>) => {
        const run = held.then(task)
        held = run.catch(() => undefined)
        return run
      }
    }
    Object.defineProperty(navigator, 'locks', { value: locks, configurable: true })
  })

  afterEach(() => {
    Object.defineProperty(navigator, 'locks', { value: undefined, configurable: true })
  })

  it('refreshes once, and the other tab takes the token it wrote', async () => {
    local.setItem('token', JSON.stringify({ refresh_token: 'r1', access_token: 'stale', token_type: 'Bearer', expires: Date.now() - 1 }))
    const functions = mockOAuthFunctions()
    functions.refresh.mockImplementation(async () => {
      await new Promise(resolve => setTimeout(resolve, 5))
      return { access_token: 'fresh', refresh_token: 'r2', token_type: 'Bearer', expires_in: 60 }
    })
    const config = { config: { tokenPath: '/t', clientId: 'c' }, functions }
    const first = create(config)
    const second = create(config)

    await Promise.all([first.checkToken(), second.checkToken()])

    expect(functions.refresh).toHaveBeenCalledTimes(1)
    expect(first.token().refresh_token).toBe('r2')
    expect(second.token().refresh_token).toBe('r2')
    first.dispose()
    second.dispose()
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
