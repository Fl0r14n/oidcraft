import { beforeEach, describe, expect, it } from 'bun:test'
import { OAuthStatus } from '@oidcraft/core'
import { createApp, nextTick } from 'vue'
import { createOAuth, getActiveOAuth, useOAuth, useOAuthUser } from './module'

/** A localStorage the tests own, so persistence can be asserted rather than assumed. */
const installStorage = () => {
  const m = new Map<string, string>()
  const storage = {
    getItem: (k: string) => (m.has(k) ? (m.get(k) as string) : null),
    setItem: (k: string, v: string) => void m.set(k, String(v)),
    removeItem: (k: string) => void m.delete(k),
    clear: () => m.clear(),
    key: (i: number) => [...m.keys()][i] ?? null,
    get length() {
      return m.size
    }
  } as Storage
  Object.defineProperty(globalThis, 'localStorage', { value: storage, configurable: true, writable: true })
  return storage
}

const local = installStorage()
const config = { issuerPath: 'https://idp', clientId: 'c', tokenPath: 'https://idp/token' }

describe('the reactive bridge', () => {
  beforeEach(() => local.clear())

  it('reflects a core write in a ref', async () => {
    const oauth = createOAuth({ config, functions: { refresh: async t => t } })

    oauth.token.value = { access_token: 'a', token_type: 'Bearer' }
    await nextTick()

    expect(oauth.token.value.access_token).toBe('a')
    expect(oauth.accessToken.value).toBe('Bearer a')
    expect(oauth.isAuthorized.value).toBe(true)
    expect(oauth.status.value).toBe(OAuthStatus.AUTHORIZED)
    oauth.dispose()
  })

  // the write must reach the accessor that owns persistence, not just the ref — otherwise a redirect
  // immediately after an assignment loses the handoff it was supposed to carry
  it('writes through to storage rather than only to the ref', () => {
    const oauth = createOAuth({ config, functions: { refresh: async t => t } })

    oauth.token.value = { access_token: 'persisted', token_type: 'Bearer' }

    expect(JSON.parse(local.getItem('token') as string).access_token).toBe('persisted')
    oauth.dispose()
  })

  it('seeds from storage that was already there, which no change event would announce', () => {
    local.setItem('token', JSON.stringify({ access_token: 'restored', token_type: 'Bearer' }))

    const oauth = createOAuth({ config, functions: { refresh: async t => t } })

    expect(oauth.token.value.access_token).toBe('restored')
    expect(oauth.isAuthorized.value).toBe(true)
    oauth.dispose()
  })

  it('derives every flag from one token, so they cannot disagree', () => {
    const oauth = createOAuth({ config, functions: { refresh: async t => t } })

    oauth.token.value = { error: 'access_denied', error_description: 'no' }

    expect(oauth.status.value).toBe(OAuthStatus.DENIED)
    expect(oauth.hasError.value).toBe(true)
    expect(oauth.error.value).toBe('access_denied')
    expect(oauth.errorDescription.value).toBe('no')
    expect(oauth.isAuthorized.value).toBe(false)
    oauth.dispose()
  })

  it('merges into the config through the writable ref', () => {
    const oauth = createOAuth({ config, functions: { refresh: async t => t } })

    oauth.typeConfig.value = { scope: 'openid email' }

    expect(oauth.typeConfig.value?.scope).toBe('openid email')
    // merged, not replaced: discovery fills this config in field by field
    expect((oauth.typeConfig.value as { clientId?: string })?.clientId).toBe('c')
    oauth.dispose()
  })

  // a detached scope owns subscriptions no component will ever stop, which is what makes one instance
  // per request safe on a server and a leak if nobody disposes it
  it('stops following the core once disposed', () => {
    const oauth = createOAuth({ config, functions: { refresh: async t => t } })
    oauth.token.value = { access_token: 'before', token_type: 'Bearer' }
    const before = oauth.token.value

    oauth.dispose()
    // the write still reaches storage — the setter is the core's — but nothing is following it back
    oauth.token.value = { access_token: 'after-dispose', token_type: 'Bearer' }

    expect(JSON.parse(local.getItem('token') as string).access_token).toBe('after-dispose')
    expect(oauth.token.value).toBe(before)
    expect(oauth.token.value.access_token).toBe('before')
  })
})

describe('injection', () => {
  beforeEach(() => local.clear())

  it('resolves through app.use and runWithContext', () => {
    const oauth = createOAuth({ config, functions: { refresh: async t => t } })
    const app = createApp({ render: () => null })
    app.use(oauth)

    expect(app.runWithContext(() => getActiveOAuth())).toBe(oauth)
    expect(app.runWithContext(() => useOAuthUser())).toBe(oauth.user)
    expect(app.runWithContext(() => useOAuth()).isAuthorized).toBe(oauth.isAuthorized)
    oauth.dispose()
  })

  it('says what to do when there is no instance in context', () => {
    expect(() => getActiveOAuth()).toThrow(/no OAuth instance in this injection context/)
  })
})
