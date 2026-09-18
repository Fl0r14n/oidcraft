import { afterEach, jest } from 'bun:test'
import type { OAuthFunctions } from '@oidcraft/core'
import { createOAuth as create, type OAuth } from './module'
import type { OAuthConfig } from './types'

/** Shared test helpers. Not part of the published build — tsdown only follows the two entry points. */

// Tests dispose what they create: bun runs every test file in one process, and an instance whose
// config watcher is still live can fire a refresh against another test's mocks.
const live: OAuth[] = []

/** Call at the top of every file using {@link createOAuth} — this module is cached, so a module-level
 * `afterEach` would register in the first importing file only. */
export const registerOAuthCleanup = () =>
  afterEach(() => {
    live.splice(0).forEach(instance => {
      instance.dispose()
    })
  })

export const createOAuth = (cfg?: OAuthConfig): OAuth => {
  const instance = create(cfg)
  live.push(instance)
  return instance
}

/** Typed mocks, so a test never reaches the network. */
export const mockOAuthFunctions = () => ({
  refresh: jest.fn<OAuthFunctions['refresh']>(),
  revoke: jest.fn<OAuthFunctions['revoke']>(),
  authorize: jest.fn<OAuthFunctions['authorize']>(),
  // deliberately not mocked: `beginAuthorization` routes through it, and the URL it builds is what
  // the flow tests are asserting on
  resourceOwnerLogin: jest.fn<OAuthFunctions['resourceOwnerLogin']>(),
  clientCredentialLogin: jest.fn<OAuthFunctions['clientCredentialLogin']>(),
  openIdConfiguration: jest.fn<OAuthFunctions['openIdConfiguration']>(),
  userInfo: jest.fn<OAuthFunctions['userInfo']>(),
  introspect: jest.fn<OAuthFunctions['introspect']>()
})

/** A `localStorage` tests can clear deterministically between files. `storage.ts` reads the global
 * lazily, so installing this after import is enough. */
export const installStorage = (): Storage => {
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

/** Unsigned id_token — enough for the unverified `parseIdToken` path. */
export const idToken = (payload: object) => {
  const b64 = (value: string) =>
    btoa(String.fromCharCode(...new TextEncoder().encode(value)))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '')
  return `${b64(JSON.stringify({ alg: 'none' }))}.${b64(JSON.stringify(payload))}.sig`
}

/**
 * bun test runs in a bare runtime. The client layer needs exactly these browser globals, so they are
 * shimmed rather than satisfied with a DOM implementation: registering happy-dom would also replace
 * `fetch` with one routed through `node:http`, and the server tests sharing this process talk to a
 * `Bun.serve` origin that shim mis-parses.
 */
const installDom = () => {
  const global = globalThis as any
  if (typeof global.window === 'undefined') global.window = globalThis
  if (typeof global.location === 'undefined') {
    // plain and mutable: tests replace `location.replace` to capture navigations, which a real
    // Location does not allow
    global.location = { href: 'http://localhost/', origin: 'http://localhost', pathname: '/', search: '', hash: '', replace: () => {} }
  }
  if (typeof global.StorageEvent === 'undefined') {
    global.StorageEvent = class StorageEvent extends Event {
      readonly key: string | null
      readonly newValue: string | null
      readonly oldValue: string | null
      constructor(type: string, init: { key?: string | null; newValue?: string | null; oldValue?: string | null } = {}) {
        super(type)
        this.key = init.key ?? null
        this.newValue = init.newValue ?? null
        this.oldValue = init.oldValue ?? null
      }
    }
  }
}

installDom()

/** Lets the watchers' async callbacks settle. */
export const flush = () => new Promise(resolve => setTimeout(resolve, 0))
