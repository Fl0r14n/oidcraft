import { afterEach, beforeEach, describe, expect, it } from 'bun:test'
import { OAuthType } from '@oidcraft/core'
import type { OAuth } from './module'
import { createOAuth, installStorage, mockOAuthFunctions as mocked, registerOAuthCleanup } from './test-utils'
import type { OAuthConfig } from './types'

const local = installStorage()
registerOAuthCleanup()

describe('login', () => {
  let oauth: OAuth
  let functions: ReturnType<typeof mocked>

  beforeEach(() => {
    local.clear()
    functions = mocked()
    oauth = createOAuth({ config: { tokenPath: '/t', clientId: 'c' }, functions })
  })

  it('uses the resource-owner grant when given a password', async () => {
    functions.resourceOwnerLogin.mockResolvedValue({ access_token: 'ro', type: OAuthType.RESOURCE })

    await oauth.login({ username: 'u', password: 'p' })

    expect(functions.resourceOwnerLogin).toHaveBeenCalledWith({ username: 'u', password: 'p' }, { tokenPath: '/t', clientId: 'c' })
    expect(functions.clientCredentialLogin).not.toHaveBeenCalled()
    expect(oauth.token().access_token).toBe('ro')
  })

  it('falls back to client_credentials with no parameters', async () => {
    functions.clientCredentialLogin.mockResolvedValue({ access_token: 'cc', type: OAuthType.CLIENT_CREDENTIAL })

    await oauth.login()

    expect(functions.clientCredentialLogin).toHaveBeenCalled()
    expect(oauth.token().type).toBe(OAuthType.CLIENT_CREDENTIAL)
  })

  it('stores an empty token when the grant returns nothing', async () => {
    functions.resourceOwnerLogin.mockResolvedValue(undefined)

    await oauth.login({ username: 'u', password: 'p' })

    expect(oauth.token()).toEqual({})
  })
})

describe('login — authorization redirect', () => {
  let oauth: OAuth

  beforeEach(() => {
    local.clear()
  })

  const build = (config: Record<string, unknown>) => {
    oauth = createOAuth({
      config: { tokenPath: '/t', clientId: 'c', authorizePath: 'https://idp/auth', ...config } as any,
      functions: mocked()
    })
    return oauth
  }

  it('builds the authorize url with the standard parameters', async () => {
    const url = await build({ scope: 'basic' }).login({ redirectUri: 'https://app/cb', responseType: OAuthType.AUTHORIZATION_CODE })

    const params = new URL(url!).searchParams
    expect(params.get('client_id')).toBe('c')
    expect(params.get('redirect_uri')).toBe('https://app/cb')
    expect(params.get('response_type')).toBe('code')
    expect(params.get('scope')).toBe('basic')
    // no openid scope → no nonce, no pkce configured → no challenge
    expect(params.get('nonce')).toBeNull()
    expect(params.get('code_challenge')).toBeNull()
  })

  it('adds a nonce for openid scope and stores it for the callback to verify', async () => {
    const url = await build({ scope: 'openid profile' }).login({
      redirectUri: 'https://app/cb',
      responseType: OAuthType.AUTHORIZATION_CODE
    })

    const nonce = new URL(url!).searchParams.get('nonce')
    expect(nonce).toBeTruthy()
    expect(oauth.token().nonce).toBe(nonce!)
  })

  it('adds an S256 challenge and keeps the verifier when pkce is on', async () => {
    const url = await build({ scope: 'openid', pkce: true }).login({
      redirectUri: 'https://app/cb',
      responseType: OAuthType.AUTHORIZATION_CODE
    })

    const params = new URL(url!).searchParams
    expect(params.get('code_challenge_method')).toBe('S256')
    expect(params.get('code_challenge')).toBeTruthy()
    // the verifier stays local — it is what proves ownership of the challenge at token exchange
    expect(oauth.token().code_verifier).toBeTruthy()
    expect(params.get('code_challenge')).not.toBe(oauth.token().code_verifier)
  })

  it('names the problem when authorizePath is missing', async () => {
    // reachable without a config typo: discovery failing leaves authorizePath unset, and the old
    // behaviour was `Cannot read properties of undefined (reading 'includes')`
    const oauth = createOAuth({ config: { clientId: 'c' } as any, functions: mocked() })

    await expect(oauth.login({ redirectUri: 'https://app/cb', responseType: OAuthType.AUTHORIZATION_CODE })).rejects.toThrow(
      /no authorizePath/
    )
  })

  it('does not carry a previous session error into the new attempt', async () => {
    // a dead session leaves {error, error_description} in the token; merging the new attempt on top
    // of it meant a successful re-login still reported the old failure
    build({ scope: 'openid' })
    oauth.setToken({ error: 'invalid_request', error_description: 'Invalid Credentials' })

    await oauth.login({ redirectUri: 'https://app/cb', responseType: OAuthType.AUTHORIZATION_CODE })

    expect(oauth.token().error).toBeUndefined()
    expect(oauth.token().error_description).toBeUndefined()
    expect(oauth.hasError()).toBe(false)
    // the parameters the new attempt actually needs are still there
    expect(oauth.token().nonce).toBeTruthy()
    expect(oauth.token().redirect_uri).toBe('https://app/cb')
  })

  it('passes access_type and prompt through for offline consent', async () => {
    const url = await build({}).login({
      redirectUri: 'https://app/cb',
      responseType: OAuthType.AUTHORIZATION_CODE,
      accessType: 'offline',
      prompt: 'consent'
    })

    const params = new URL(url!).searchParams
    expect(params.get('access_type')).toBe('offline')
    expect(params.get('prompt')).toBe('consent')
  })
})

describe('logout', () => {
  let oauth: OAuth
  let functions: ReturnType<typeof mocked>

  const build = (cfg?: OAuthConfig) => {
    functions = mocked()
    oauth = createOAuth({ config: { tokenPath: '/t', clientId: 'c' }, functions, ...cfg })
    return oauth
  }

  beforeEach(() => {
    local.clear()
  })

  it('revokes and clears the token when there is no hosted logout', async () => {
    build()
    oauth.setToken({ access_token: 'at' })

    await oauth.logout()

    expect(functions.revoke).toHaveBeenCalled()
    expect(oauth.token()).toEqual({})
  })

  it('clears the token even when revocation fails', async () => {
    // the IdP answers 4xx for an already-invalid token (Google does). If that aborts the logout, the
    // session survives, the next call 401s, and the interceptor refills the token with the IdP's
    // error — which is how a logout ends up showing "Invalid Credentials".
    build()
    functions.revoke.mockRejectedValue(new Error('400 from the revocation endpoint'))
    oauth.setToken({ access_token: 'stale', token_type: 'Bearer' })

    await expect(oauth.logout()).rejects.toThrow()

    expect(oauth.token()).toEqual({})
    expect(oauth.isAuthorized()).toBe(false)
  })

  it('clears the token before redirecting to the hosted end-session endpoint', async () => {
    build({ config: { tokenPath: '/t', clientId: 'c', logoutPath: 'https://idp/logout' } })
    oauth.setToken({ access_token: 'at', id_token: 'idt' })

    await oauth.logout('https://app/')

    // the redirect itself is a no-op in the test environment; what matters is that the local
    // session is dropped rather than left behind if the navigation never happens
    expect(functions.revoke).not.toHaveBeenCalled()
    expect(oauth.token()).toEqual({})
  })
})

describe('oauthCallback', () => {
  let oauth: OAuth
  let functions: ReturnType<typeof mocked>

  beforeEach(() => {
    local.clear()
    functions = mocked()
    oauth = createOAuth({ config: { tokenPath: '/t', clientId: 'c', authorizePath: '/a' }, functions })
  })

  it('ignores a url with neither a code nor a token', async () => {
    await oauth.oauthCallback('https://h/callback')
    expect(functions.authorize).not.toHaveBeenCalled()
    expect(oauth.token()).toEqual({})
  })

  it('exchanges an authorization code and records the state', async () => {
    functions.authorize.mockResolvedValue({ access_token: 'coded', type: OAuthType.AUTHORIZATION_CODE })

    await oauth.oauthCallback('https://h/callback?code=abc&state=xyz')

    expect(functions.authorize).toHaveBeenCalled()
    expect(oauth.state()).toBe('xyz')
    expect(oauth.token().access_token).toBe('coded')
  })

  it('keeps an error response from the authorization server', async () => {
    functions.authorize.mockResolvedValue({ error: 'access_denied' })

    await oauth.oauthCallback('https://h/callback?error=access_denied')

    expect(oauth.token().error).toBe('access_denied')
    expect(oauth.hasError()).toBe(true)
  })

  it('accepts an implicit redirect from the fragment and marks the grant', async () => {
    await oauth.oauthCallback('https://h/callback#access_token=implicit&token_type=Bearer&state=st')

    expect(oauth.token().access_token).toBe('implicit')
    expect(oauth.token().type).toBe(OAuthType.IMPLICIT)
    expect(oauth.state()).toBe('st')
  })

  it('rejects an implicit redirect whose id_token nonce does not match the stored one', async () => {
    oauth.setToken({ nonce: 'expected' })

    // an id_token with no nonce claim at all — the classic replay of a token minted for someone else
    await oauth.oauthCallback(`https://h/callback#access_token=implicit&id_token=${'header.e30.sig'}`)

    expect(oauth.token().error).toBe('Invalid nonce')
  })

  it('exchanges a given code once even when called concurrently', async () => {
    // StrictMode double-invokes effects, so both calls start before either resolves
    functions.authorize.mockResolvedValue({ access_token: 'coded', type: OAuthType.AUTHORIZATION_CODE })
    const url = 'https://h/callback?code=abc&state=xyz'

    await Promise.all([oauth.oauthCallback(url), oauth.oauthCallback(url)])

    expect(functions.authorize).toHaveBeenCalledTimes(1)
    expect(oauth.token().access_token).toBe('coded')
  })

  it('does not re-exchange a code that has already been exchanged', async () => {
    // a browser Back into the callback URL. Re-exchanging a consumed code does not fail harmlessly:
    // the IdP answers invalid_grant, which would land in the token and kill a live session
    functions.authorize.mockResolvedValue({ access_token: 'coded', type: OAuthType.AUTHORIZATION_CODE })
    const url = 'https://h/callback?code=abc'

    await oauth.oauthCallback(url)
    await oauth.oauthCallback(url)

    expect(functions.authorize).toHaveBeenCalledTimes(1)
    expect(oauth.token().access_token).toBe('coded')
    expect(oauth.hasError()).toBe(false)
  })

  it('still handles a genuinely different redirect', async () => {
    functions.authorize.mockResolvedValue({ access_token: 'first', type: OAuthType.AUTHORIZATION_CODE })
    await oauth.oauthCallback('https://h/callback?code=one')

    functions.authorize.mockResolvedValue({ access_token: 'second', type: OAuthType.AUTHORIZATION_CODE })
    await oauth.oauthCallback('https://h/callback?code=two')

    expect(functions.authorize).toHaveBeenCalledTimes(2)
    expect(oauth.token().access_token).toBe('second')
  })

  it('scopes the dedupe to the instance, so a fresh instance re-runs the same url', async () => {
    functions.authorize.mockResolvedValue({ access_token: 'coded', type: OAuthType.AUTHORIZATION_CODE })
    const url = 'https://h/callback?code=abc'
    await oauth.oauthCallback(url)

    const other = createOAuth({ config: { tokenPath: '/t', clientId: 'c' }, functions })
    await other.oauthCallback(url)

    expect(functions.authorize).toHaveBeenCalledTimes(2)
  })
})

describe('redirect: false', () => {
  let oauth: OAuth
  let replaced: string[]
  let restore: () => void

  beforeEach(() => {
    local.clear()
    replaced = []
    const location = globalThis.location as Location & { replace: (url: string) => void }
    const original = location.replace
    location.replace = (url: string) => void replaced.push(url)
    restore = () => {
      location.replace = original
    }
  })

  afterEach(() => restore())

  it('login returns the authorize url without navigating', async () => {
    oauth = createOAuth({
      config: { tokenPath: '/t', clientId: 'c', authorizePath: 'https://idp/auth', scope: 'openid', pkce: true } as any,
      functions: mocked()
    })

    const url = await oauth.login({ redirectUri: 'https://app/cb', responseType: OAuthType.AUTHORIZATION_CODE }, { redirect: false })

    expect(url).toContain('https://idp/auth?')
    expect(replaced).toEqual([])
    // the flow is still armed: without these persisted, the caller's own navigation leads to a
    // callback that cannot complete
    expect(oauth.token().code_verifier).toBeTruthy()
    expect(oauth.token().nonce).toBeTruthy()
    expect(oauth.token().redirect_uri).toBe('https://app/cb')
  })

  it('login navigates by default', async () => {
    oauth = createOAuth({
      config: { tokenPath: '/t', clientId: 'c', authorizePath: 'https://idp/auth' } as any,
      functions: mocked()
    })

    const url = await oauth.login({ redirectUri: 'https://app/cb', responseType: OAuthType.AUTHORIZATION_CODE })

    expect(replaced).toEqual([url!])
  })

  it('logout returns the end-session url without navigating, and still drops the session', async () => {
    oauth = createOAuth({
      config: { tokenPath: '/t', clientId: 'c', logoutPath: 'https://idp/logout' },
      functions: mocked()
    })
    oauth.setToken({ access_token: 'at', id_token: 'idt' })

    const url = await oauth.logout('https://app/', undefined, { redirect: false })

    expect(url).toContain('https://idp/logout?')
    expect(new URL(url!).searchParams.get('post_logout_redirect_uri')).toBe('https://app/')
    expect(new URL(url!).searchParams.get('id_token_hint')).toBe('idt')
    expect(replaced).toEqual([])
    expect(oauth.token()).toEqual({})
  })

  it('logout returns undefined when there is nothing to visit', async () => {
    oauth = createOAuth({ config: { tokenPath: '/t', clientId: 'c' }, functions: mocked() })
    oauth.setToken({ access_token: 'at' })

    expect(await oauth.logout()).toBeUndefined()
  })
})
