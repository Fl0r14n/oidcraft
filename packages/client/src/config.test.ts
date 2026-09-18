import { beforeEach, describe, expect, it, jest } from 'bun:test'
import { defaultOAuthFunctions } from '@oidcraft/core'
import { createOAuth, installStorage, mockOAuthFunctions, registerOAuthCleanup } from './test-utils'

const local = installStorage()
registerOAuthCleanup()

beforeEach(() => {
  local.clear()
})

describe('config', () => {
  it('applies defaults', () => {
    const oauth = createOAuth()

    expect(oauth.storageKey()).toBe('token')
    expect(oauth.oauthConfig().ignorePaths).toEqual([])
    expect(oauth.strictJwt()).toBe(true)
  })

  it('merges the given config over the defaults', () => {
    const oauth = createOAuth({
      storageKey: 'custom',
      strictJwt: false,
      config: { clientId: 'c', tokenPath: '/t' }
    })

    expect(oauth.storageKey()).toBe('custom')
    expect(oauth.strictJwt()).toBe(false)
    expect(oauth.config()).toEqual({ clientId: 'c', tokenPath: '/t' })
  })

  it('setConfig merges instead of replacing', () => {
    const oauth = createOAuth({ config: { clientId: 'c' } })

    oauth.setConfig({ tokenPath: '/t' })

    expect(oauth.config()).toEqual({ clientId: 'c', tokenPath: '/t' })
  })

  it('merges functions overrides over the defaults', () => {
    const refresh = jest.fn()
    const oauth = createOAuth({ functions: { refresh } })

    expect(oauth.functions.refresh).toBe(refresh)
    expect(oauth.functions.revoke).toBe(defaultOAuthFunctions.revoke)
  })

  it('ignorePath registers interceptor exclusions idempotently', () => {
    const oauth = createOAuth()

    oauth.ignorePath(/\/authorizationserver/)
    oauth.ignorePath(/\/authorizationserver/) // factories may run more than once
    oauth.ignorePath(/\/other/)

    expect(oauth.oauthConfig().ignorePaths?.map(p => p.source)).toEqual(['\\/authorizationserver', '\\/other'])
  })

  it('isPathIgnored matches any registered pattern', () => {
    const oauth = createOAuth({ ignorePaths: [/public/] })

    expect(oauth.isPathIgnored('/api/public/products')).toBe(true)
    expect(oauth.isPathIgnored('/api/orders')).toBe(false)
    expect(oauth.isPathIgnored(undefined)).toBe(false)
  })

  it('isPathIgnored matches an anchored pattern against the pathname of an absolute URL', () => {
    const oauth = createOAuth({ ignorePaths: [/^\/public/] })

    // the natural way to write this, and it never fired for an absolute URL when only the raw string
    // was tested — `^` cannot match past `https://host`
    expect(oauth.isPathIgnored('/public/products')).toBe(true)
    expect(oauth.isPathIgnored('https://api.example.com/public/products')).toBe(true)
    expect(oauth.isPathIgnored('https://api.example.com/orders')).toBe(false)
  })

  it('isPathIgnored still honours a pattern written against the host', () => {
    const oauth = createOAuth({ ignorePaths: [/cdn\.example\.com/] })

    // matching only the pathname instead would have silently broken this
    expect(oauth.isPathIgnored('https://cdn.example.com/assets/logo.svg')).toBe(true)
    expect(oauth.isPathIgnored('https://api.example.com/assets/logo.svg')).toBe(false)
  })

  it('isPathIgnored lets an end-anchored pattern past a query string', () => {
    const oauth = createOAuth({ ignorePaths: [/^\/public$/] })

    expect(oauth.isPathIgnored('https://api.example.com/public?page=2')).toBe(true)
  })

  it('keeps config isolated between instances', () => {
    const first = createOAuth({ config: { clientId: 'first' } })
    const second = createOAuth({ config: { clientId: 'second' } })

    expect(first.config()?.clientId).toBe('first')
    expect(second.config()?.clientId).toBe('second')
  })

  it('rekeys the token store when storageKey changes — the multi-tenant case', () => {
    local.setItem('site-a.token', JSON.stringify({ access_token: 'a' }))
    local.setItem('site-b.token', JSON.stringify({ access_token: 'b' }))
    const oauth = createOAuth({ storageKey: 'site-a.token', functions: mockOAuthFunctions() })
    expect(oauth.token().access_token).toBe('a')

    oauth.setStorageKey('site-b.token')

    expect(oauth.token().access_token).toBe('b')
  })
})
