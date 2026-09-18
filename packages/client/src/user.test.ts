import { beforeEach, describe, expect, it } from 'bun:test'
import type { UserInfo } from '@oidcraft/core'
import type { OAuth } from './module'
import { createOAuth, flush, idToken, installStorage, mockOAuthFunctions, registerOAuthCleanup } from './test-utils'

const local = installStorage()
registerOAuthCleanup()

describe('user', () => {
  let oauth: OAuth
  let userInfo: ReturnType<typeof mockOAuthFunctions>['userInfo']

  beforeEach(() => {
    local.clear()
    const functions = mockOAuthFunctions()
    userInfo = functions.userInfo
    oauth = createOAuth({ functions })
  })

  it('derives the user from the id_token claims', async () => {
    oauth.setToken({ id_token: idToken({ name: 'Jane', email: 'jane@acme.io' }) })

    await flush()

    expect(oauth.user()).toMatchObject({ name: 'Jane', email: 'jane@acme.io' })
  })

  it('fetches userinfo once authorized and a userPath is configured', async () => {
    userInfo.mockResolvedValue({ name: 'From Endpoint' })
    oauth.setConfig({ userPath: '/userinfo' } as any)
    oauth.setToken({ access_token: 'at', token_type: 'Bearer' })

    await flush()

    expect(userInfo).toHaveBeenCalledWith(oauth.config(), oauth.fetch)
    expect(oauth.user()).toEqual({ name: 'From Endpoint' })
  })

  it('fetches userinfo on creation with a stored token and a static userPath', async () => {
    const functions = mockOAuthFunctions()
    functions.userInfo.mockResolvedValue({ name: 'Restored' })
    // token already in storage + userPath configured up front: neither watch source ever changes
    local.setItem('token', JSON.stringify({ access_token: 'at', token_type: 'Bearer', expires: Date.now() + 60_000 }))
    const restored = createOAuth({ functions, config: { userPath: '/userinfo' } as any })

    await flush()

    expect(functions.userInfo).toHaveBeenCalled()
    expect(restored.user()).toEqual({ name: 'Restored' })
  })

  it('fetches userinfo once per session change, not once per write', async () => {
    userInfo.mockResolvedValue({ name: 'From Endpoint' })
    oauth.setConfig({ userPath: '/userinfo' } as any)
    oauth.setToken({ access_token: 'at', token_type: 'Bearer', expires_in: 60 })
    await flush()
    // the id_token and the authorized flag are watched as one tuple, so a single token write is a single
    // sync however many fields it moved — and checkToken's expires write does not move either of them
    await oauth.checkToken()
    await flush()

    expect(userInfo).toHaveBeenCalledTimes(1)
  })

  it('does not fetch userinfo without a userPath', async () => {
    oauth.setToken({ access_token: 'at', token_type: 'Bearer' })

    await flush()

    expect(userInfo).not.toHaveBeenCalled()
  })

  it('keeps user state isolated between instances', async () => {
    oauth.setToken({ id_token: idToken({ name: 'Jane' }) })
    // own storageKey: instances sharing a key legitimately share the persisted token
    const second = createOAuth({ storageKey: 'second.token', functions: mockOAuthFunctions() })

    await flush()

    expect(oauth.user()).toMatchObject({ name: 'Jane' })
    expect(second.user()).toBeUndefined()
  })

  it('clears the user when the token goes away', async () => {
    oauth.setToken({ id_token: idToken({ name: 'Jane' }) })
    await flush()
    expect(oauth.user()).toMatchObject({ name: 'Jane' })

    // what logout() without a redirect does, and what the 401 handler and a failed refresh do too
    oauth.setToken({})
    await flush()

    expect(oauth.user()).toBeUndefined()
  })

  it('clears the user on a local logout', async () => {
    userInfo.mockResolvedValue({ name: 'From Endpoint' })
    oauth.setConfig({ userPath: '/userinfo' } as any)
    oauth.setToken({ access_token: 'at', token_type: 'Bearer' })
    await flush()
    expect(oauth.user()).toEqual({ name: 'From Endpoint' })

    // no logoutPath configured, so this revokes locally instead of navigating away — the profile has to
    // go with the session rather than waiting for a page load that never comes
    await oauth.logout()
    await flush()

    expect(oauth.user()).toBeUndefined()
  })

  it('drops a userinfo response that arrives after the session ended', async () => {
    let resolve: (user: UserInfo) => void = () => {}
    userInfo.mockReturnValue(new Promise<UserInfo>(r => (resolve = r)))
    oauth.setConfig({ userPath: '/userinfo' } as any)
    oauth.setToken({ access_token: 'at', token_type: 'Bearer' })
    await flush()

    oauth.setToken({})
    await flush()
    // the request was in flight across the logout: landing now would put the previous user straight back
    resolve({ name: 'Too Late' })
    await flush()

    expect(oauth.user()).toBeUndefined()
  })

  it('keeps the id_token claims when there is no access token', async () => {
    // a response_type=id_token flow never produces one, and the claims are the authentication
    oauth.setToken({ id_token: idToken({ name: 'Claims Only' }) })

    await flush()

    expect(oauth.isAuthorized()).toBe(false)
    expect(oauth.user()).toMatchObject({ name: 'Claims Only' })
  })

  it('stops updating once disposed', async () => {
    oauth.dispose()

    oauth.setToken({ id_token: idToken({ name: 'Too Late' }) })
    await flush()

    expect(oauth.user()).toBeUndefined()
  })
})
