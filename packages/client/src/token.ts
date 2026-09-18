import {
  applyDiscovery,
  createDiscovery,
  type Discovery,
  needsDiscovery,
  type OAuthFunctions,
  OAuthStatus,
  type OAuthToken,
  type OAuthType,
  type OpenIdConfig
} from '@oidcraft/core'
import type { ConfigContext } from './config'
import { createStorageStore } from './storage'
import { watchStore } from './store'

export const isExpiredToken = (token?: OAuthToken) => (token?.expires && Date.now() > token.expires) || false

export interface TokenState {
  type: OAuthType | undefined
  accessToken: string | undefined
  status: OAuthStatus
  isAuthorized: boolean
  error: string | undefined
  hasError: boolean
  errorDescription: string | undefined
}

/** One pure derivation, so a binding's reactive view and the instance's own getters cannot drift. */
export const tokenState = (token?: OAuthToken): TokenState => {
  const { token_type, access_token, error, error_description, type } = token || {}
  const expired = isExpiredToken(token)
  const status = (error && OAuthStatus.DENIED) || (access_token && !expired && OAuthStatus.AUTHORIZED) || OAuthStatus.NOT_AUTHORIZED
  return {
    type,
    accessToken: (token_type && access_token && !expired && `${token_type} ${access_token}`) || undefined,
    status,
    isAuthorized: status === OAuthStatus.AUTHORIZED,
    error,
    hasError: !!error,
    errorDescription: error_description
  }
}

export const createToken = (
  { configStore, config, setConfig, storageKey }: Pick<ConfigContext, 'configStore' | 'config' | 'setConfig' | 'storageKey'>,
  functions: OAuthFunctions,
  discovery: Discovery = createDiscovery({ functions })
) => {
  const storage = createStorageStore<OAuthToken>(storageKey(), {})
  const token = storage.get
  const setToken = storage.set

  const derived = () => tokenState(token())
  const type = () => derived().type
  const accessToken = () => derived().accessToken
  const status = () => derived().status
  const isAuthorized = () => derived().isAuthorized
  const error = () => derived().error
  const hasError = () => derived().hasError
  const errorDescription = () => derived().errorDescription

  const autoconfigOauth = async () => {
    const c = (config() || {}) as OpenIdConfig
    if (!needsDiscovery(c)) return
    const discovered = await discovery(c)
    // `applyDiscovery` throws when the document asserts a different issuer than the one it came from.
    // Left to propagate on purpose: every caller of this is a login, a logout or a token check, and
    // each has somebody waiting who needs to hear it (OIDC Discovery 1.0 §4.3).
    if (discovered) setConfig(applyDiscovery(c, discovered))
  }

  const setExpires = (t: OAuthToken) => {
    const expiresIn = Number(t?.expires_in) || 0
    if (expiresIn && !t.expires) {
      setToken({ ...t, expires: Date.now() + expiresIn * 1e3 })
    }
  }

  let inFlight: Promise<void> | undefined

  const checkToken = () => {
    if (inFlight) return inFlight
    inFlight = (async () => {
      const t = token()
      if (isExpiredToken(t)) {
        await autoconfigOauth()
        const refreshed = await functions.refresh(t, config())
        if (refreshed && !isExpiredToken(refreshed)) {
          if (refreshed.error) {
            // RFC 6749 §5.2 error (invalid_grant and friends) — persisted like the 401 interceptor
            // does, so the dead token is dropped rather than retried forever
            setToken(refreshed)
          } else {
            // keep the old refresh token: the response is not required to include a new one
            setExpires({ ...(t.refresh_token && { refresh_token: t.refresh_token }), ...refreshed })
          }
        }
      } else {
        setExpires(t)
      }
    })().finally(() => {
      inFlight = undefined
    })
    return inFlight
  }

  // the raw `access_token`, not the derived `accessToken()`: that one is undefined once expired, which
  // is exactly the case this exists to refresh. A string, so a setExpires write cannot loop the watcher.
  const rawAccessToken = () => token()?.access_token
  const revalidate = () => {
    if (config() && rawAccessToken()) {
      // nobody is waiting on this one, and a discovery document that fails to validate must not become
      // an unhandled rejection. It is raised instead at the first call that has a caller.
      void checkToken().catch(() => undefined)
    }
  }

  // deferred to start() so constructing an instance is inert — see createOAuth
  let teardowns: Array<() => void> = []

  const start = () => {
    if (teardowns.length) return
    // reconcile before subscribing: the watchers fire only on *change*, so a storageKey set while the
    // instance was inert — or between a dispose and a restart — would otherwise leave the token read
    // from the old key while the config claims the new one
    storage.rekey(storageKey())
    teardowns = [
      // another tab signing in or out has to reach this one
      storage.listen(),
      // the storage key is runtime-mutable: a multi-tenant app gives each tenant its own
      watchStore(configStore, storageKey, key => storage.rekey(key)),
      watchStore(configStore, config, revalidate),
      watchStore(storage.store, rawAccessToken, revalidate)
    ]
    // a stored token may already be expired, and discovery may not have run yet
    revalidate()
  }

  return {
    tokenStore: storage.store,
    token,
    setToken,
    type,
    accessToken,
    status,
    isAuthorized,
    error,
    hasError,
    errorDescription,
    autoconfigOauth,
    checkToken,
    start,
    dispose: () => {
      for (const teardown of teardowns) {
        teardown()
      }
      teardowns = []
    }
  }
}

export type TokenContext = ReturnType<typeof createToken>
