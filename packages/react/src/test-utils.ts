import { afterEach, jest } from 'bun:test'
import { createOAuth as create, type OAuth, type OAuthConfig, type OAuthFunctions } from 'react-oauth-oidc/core'

/** Shared test helpers. Not part of the published build — tsdown only follows the four entry points. */

// Tests dispose what they create: bun runs every test file in one process, and an instance whose
// config subscription is still live can fire a refresh against another test's mocks.
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
  resourceOwnerLogin: jest.fn<OAuthFunctions['resourceOwnerLogin']>(),
  clientCredentialLogin: jest.fn<OAuthFunctions['clientCredentialLogin']>(),
  openIdConfiguration: jest.fn<OAuthFunctions['openIdConfiguration']>(),
  userInfo: jest.fn<OAuthFunctions['userInfo']>(),
  introspect: jest.fn<OAuthFunctions['introspect']>()
})

/** A `localStorage` tests can clear deterministically between files. */
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

/** Unsigned id_token — enough for the unverified parse path. */
export const idToken = (payload: object) => {
  const b64 = (value: string) =>
    btoa(String.fromCharCode(...new TextEncoder().encode(value)))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '')
  return `${b64(JSON.stringify({ alg: 'none' }))}.${b64(JSON.stringify(payload))}.sig`
}

/** Lets the subscriptions' async callbacks settle. */
export const flush = () => new Promise(resolve => setTimeout(resolve, 0))
