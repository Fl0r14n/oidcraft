import { afterEach, beforeEach, describe, expect, it } from 'bun:test'
import { Injector, runInInjectionContext } from '@angular/core'
import { OAuthStatus } from '@oidcraft/core'
import { createNgxOAuth } from './oauth'

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
const functions = { refresh: async (t?: unknown) => t as never }

/**
 * A bare `Injector.create` rather than a TestBed: the binding needs one thing from Angular — the
 * `DestroyRef` an injector already provides — so this keeps the tests free of a platform and a zone.
 *
 * The injector's own `destroy()` is what runs the teardowns; a hand-provided `DestroyRef` is ignored,
 * because Angular resolves that token from the injector itself rather than from its providers.
 */
const injectors: Array<{ destroy: () => void }> = []

const build = () => {
  const injector = Injector.create({ providers: [] }) as Injector & { destroy: () => void }
  injectors.push(injector)
  return runInInjectionContext(injector, () => createNgxOAuth({ config, functions }))
}

const destroy = () => {
  injectors.splice(0).forEach(injector => {
    injector.destroy()
  })
}

describe('the signal bridge', () => {
  beforeEach(() => local.clear())
  afterEach(destroy)

  it('reflects a core write in a signal', () => {
    const oauth = build()

    oauth.token.set({ access_token: 'a', token_type: 'Bearer' })

    expect(oauth.token().access_token).toBe('a')
    expect(oauth.accessToken()).toBe('Bearer a')
    expect(oauth.isAuthorized()).toBe(true)
    expect(oauth.status()).toBe(OAuthStatus.AUTHORIZED)
  })

  // the write has to reach the accessor that owns persistence, not just the signal — otherwise a
  // redirect straight after an assignment loses the handoff it was meant to carry
  it('writes through to storage rather than only to the signal', () => {
    const oauth = build()

    oauth.token.set({ access_token: 'persisted', token_type: 'Bearer' })

    expect(JSON.parse(local.getItem('token') as string).access_token).toBe('persisted')
  })

  it('routes update() through the same accessor', () => {
    const oauth = build()
    oauth.token.set({ access_token: 'first', token_type: 'Bearer' })

    oauth.token.update(t => ({ ...t, access_token: 'second' }))

    expect(oauth.token().access_token).toBe('second')
    expect(JSON.parse(local.getItem('token') as string).access_token).toBe('second')
  })

  it('seeds from storage that was already there, which no change event would announce', () => {
    local.setItem('token', JSON.stringify({ access_token: 'restored', token_type: 'Bearer' }))

    const oauth = build()

    expect(oauth.token().access_token).toBe('restored')
    expect(oauth.isAuthorized()).toBe(true)
  })

  it('derives every flag from one token, so they cannot disagree', () => {
    const oauth = build()

    oauth.token.set({ error: 'access_denied', error_description: 'no' })

    expect(oauth.status()).toBe(OAuthStatus.DENIED)
    expect(oauth.hasError()).toBe(true)
    expect(oauth.error()).toBe('access_denied')
    expect(oauth.errorDescription()).toBe('no')
    expect(oauth.isAuthorized()).toBe(false)
  })

  it('exposes the config and merges into it', () => {
    const oauth = build()

    oauth.setConfig({ scope: 'openid email' })

    expect(oauth.config()?.scope).toBe('openid email')
    // merged, not replaced: discovery fills this in field by field
    expect((oauth.config() as { clientId?: string })?.clientId).toBe('c')
  })

  // v8 kept the instance in module-level signals, so a second one was the same one. Per-injector is
  // what makes one instance per request safe under concurrent SSR.
  it('gives each injector its own instance', () => {
    const first = build()
    const second = build()

    first.token.set({ access_token: 'first', token_type: 'Bearer' })

    expect(second.token().access_token).not.toBe('first')
  })

  it('stops following the core once the injector is destroyed', () => {
    const oauth = build()
    oauth.token.set({ access_token: 'before', token_type: 'Bearer' })
    const before = oauth.token()

    destroy()
    oauth.token.set({ access_token: 'after-destroy', token_type: 'Bearer' })

    expect(JSON.parse(local.getItem('token') as string).access_token).toBe('after-destroy')
    expect(oauth.token()).toBe(before)
  })
})
