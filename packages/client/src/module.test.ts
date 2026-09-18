import { beforeEach, describe, expect, it } from 'bun:test'
import { OAuthType } from '@oidcraft/core'
import { createOAuth, flush, idToken, installStorage, mockOAuthFunctions, registerOAuthCleanup } from './test-utils'

const local = installStorage()
registerOAuthCleanup()

beforeEach(() => {
  local.clear()
})

describe('createOAuth', () => {
  it('holds no module-level state — instances are reachable only through the value returned', () => {
    const first = createOAuth({ storageKey: 'a', functions: mockOAuthFunctions() })
    const second = createOAuth({ storageKey: 'b', functions: mockOAuthFunctions() })

    // creating the second must not disturb the first in any way. Under a last-one-wins module pointer
    // this is where one request started answering with another request's instance.
    first.setToken({ access_token: 'first', type: OAuthType.RESOURCE })
    second.dispose()

    expect(first.token().access_token).toBe('first')
    expect(first.isAuthorized()).toBe(true)
  })
})

describe('autoStart / start()', () => {
  const expiredToken = { access_token: 'at', token_type: 'Bearer', refresh_token: 'rt', expires: Date.now() - 1_000 }

  it('touches nothing until start() when autoStart is false', async () => {
    local.setItem('inert', JSON.stringify(expiredToken))
    const functions = mockOAuthFunctions()
    functions.refresh.mockResolvedValue({ access_token: 'fresh', token_type: 'Bearer', expires_in: 3600 })

    const oauth = createOAuth({ storageKey: 'inert', config: { tokenPath: '/t', clientId: 'c' }, functions, autoStart: false })
    await flush()

    // the stored token is expired, so an instance that observed anything would already have refreshed
    expect(functions.refresh).not.toHaveBeenCalled()
    expect(oauth.token().access_token).toBe('at')

    oauth.start()
    await flush()

    expect(functions.refresh).toHaveBeenCalled()
    expect(oauth.token().access_token).toBe('fresh')
  })

  it('revalidates on construction by default', async () => {
    local.setItem('eager', JSON.stringify(expiredToken))
    const functions = mockOAuthFunctions()
    functions.refresh.mockResolvedValue({ access_token: 'fresh', token_type: 'Bearer', expires_in: 3600 })

    createOAuth({ storageKey: 'eager', config: { tokenPath: '/t', clientId: 'c' }, functions })
    await flush()

    expect(functions.refresh).toHaveBeenCalled()
  })

  it('start() reconciles a storageKey that changed while inert', () => {
    local.setItem('tenant-a', JSON.stringify({ access_token: 'a' }))
    local.setItem('tenant-b', JSON.stringify({ access_token: 'b' }))
    const oauth = createOAuth({ storageKey: 'tenant-a', functions: mockOAuthFunctions(), autoStart: false })

    oauth.setStorageKey('tenant-b')
    // nothing is watching yet, so the token still comes from tenant-a
    expect(oauth.token().access_token).toBe('a')

    oauth.start()

    // start reconciles rather than only subscribing — the watchers fire on change, and this was not one
    expect(oauth.token().access_token).toBe('b')
  })

  it('start() is idempotent — watchers are attached once', async () => {
    local.setItem('once', JSON.stringify({ access_token: 'at', token_type: 'Bearer' }))
    const functions = mockOAuthFunctions()
    functions.userInfo.mockResolvedValue({ sub: 'abc' })
    const oauth = createOAuth({ storageKey: 'once', config: { tokenPath: '/t', clientId: 'c', userPath: '/me' }, functions })
    await flush()
    const callsAfterFirstStart = functions.userInfo.mock.calls.length

    oauth.start()
    oauth.start()
    await flush()

    expect(functions.userInfo.mock.calls.length).toBe(callsAfterFirstStart)
  })

  it('re-arms after a dispose', async () => {
    local.setItem('rearm', JSON.stringify({ access_token: 'at', token_type: 'Bearer' }))
    const functions = mockOAuthFunctions()
    const oauth = createOAuth({ storageKey: 'rearm', config: { tokenPath: '/t', clientId: 'c' }, functions })
    oauth.dispose()

    // disposed: the id_token watcher is gone, so the user is not decoded
    oauth.setToken({ id_token: idToken({ name: 'Ignored' }) })
    await flush()
    expect(oauth.user()).toBeUndefined()

    oauth.start()
    oauth.setToken({ id_token: idToken({ name: 'Jane' }) })
    await flush()

    expect(oauth.user()?.name).toBe('Jane')
  })
})

describe('instance isolation', () => {
  it('gives concurrent requests separate tokens and axios instances', () => {
    const first = createOAuth({ storageKey: 'site-a.token', functions: mockOAuthFunctions() })
    const second = createOAuth({ storageKey: 'site-b.token', functions: mockOAuthFunctions() })

    first.setToken({ access_token: 'first', type: OAuthType.RESOURCE })
    second.setToken({ access_token: 'second', type: OAuthType.CLIENT_CREDENTIAL })

    expect(first.token().access_token).toBe('first')
    expect(second.token().access_token).toBe('second')
    // separate authorized transports: each closes over one request's token, never the other's
    expect(first.fetch).not.toBe(second.fetch)
  })

  it('exposes a writable token — a punch-out session assigns one directly', () => {
    const oauth = createOAuth({ storageKey: 'punchout', functions: mockOAuthFunctions() })

    oauth.setToken({ access_token: 'injected', token_type: 'Bearer', type: OAuthType.RESOURCE, expires_in: 3600 })

    expect(oauth.accessToken()).toBe('Bearer injected')
    expect(oauth.type()).toBe(OAuthType.RESOURCE)
  })

  it('dispose stops the watchers but leaves the store usable', () => {
    const oauth = createOAuth({ storageKey: 'disposed', functions: mockOAuthFunctions() })

    oauth.dispose()
    oauth.setToken({ access_token: 'still-settable' })

    expect(oauth.token().access_token).toBe('still-settable')
  })

  it('dispose is idempotent', () => {
    const oauth = createOAuth({ storageKey: 'twice', functions: mockOAuthFunctions() })

    oauth.dispose()
    oauth.dispose()

    // the watchers are gone, but the stores still answer — nothing threw on the second teardown
    oauth.setToken({ access_token: 'after-double-dispose' })
    expect(oauth.token().access_token).toBe('after-double-dispose')
  })
})
