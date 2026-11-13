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

const refreshAhead = (token: OAuthToken) => Math.min(30_000, ((Number(token.expires_in) || Number.POSITIVE_INFINITY) * 1e3) / 2)
const isExpiringToken = (token?: OAuthToken) => (token?.expires && Date.now() + refreshAhead(token) > token.expires) || false

// FR-L5: Web Locks span the origin's tabs; without them, this tab alone.
const exclusively = (name: string, task: () => Promise<void>): Promise<void> => {
  const locks = globalThis.navigator?.locks
  return locks ? locks.request(name, task) : task()
}

export interface TokenState {
  type: OAuthType | undefined
  accessToken: string | undefined
  status: OAuthStatus
  isAuthorized: boolean
  error: string | undefined
  hasError: boolean
  errorDescription: string | undefined
}

/** The derived token state a binding renders and the instance's getters read. */
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
    // an issuer mismatch throws from `applyDiscovery` and propagates to the caller (OIDC Discovery 1.0 §4.3)
    if (discovered) setConfig(applyDiscovery(c, discovered))
  }

  const withExpiry = (t: OAuthToken) => {
    const expiresIn = Number(t?.expires_in) || 0
    return expiresIn && !t.expires ? { ...t, expires: Date.now() + expiresIn * 1e3 } : t
  }

  const setExpires = (t: OAuthToken) => {
    const dated = withExpiry(t)
    if (dated !== t) setToken(dated)
  }

  let inFlight: Promise<void> | undefined

  const checkToken = () => {
    if (inFlight) return inFlight
    inFlight = (async () => {
      if (!isExpiringToken(token())) {
        setExpires(token())
        return
      }
      await exclusively(`oidcraft.refresh.${storageKey()}`, async () => {
        // FR-L5, FR-T3: another tab may have rotated the refresh token while this one waited
        storage.reload()
        const t = token()
        if (!isExpiringToken(t)) return
        await autoconfigOauth()
        const refreshed = await functions.refresh(t, config())
        if (refreshed && !isExpiredToken(refreshed)) {
          if (refreshed.error) {
            setToken(refreshed)
          } else {
            // FR-L5: stored even without an expiry; RFC 6749 §6 and OIDC Core §12.2 let it omit the refresh and ID tokens
            const kept = { ...(t.refresh_token && { refresh_token: t.refresh_token }), ...(t.id_token && { id_token: t.id_token }) }
            setToken(withExpiry({ ...kept, ...refreshed }))
          }
        }
      })
    })().finally(() => {
      inFlight = undefined
    })
    return inFlight
  }

  // raw, not `accessToken()`, which is undefined once expired: the very case this refreshes
  const rawAccessToken = () => token()?.access_token
  const revalidate = () => {
    if (config() && rawAccessToken()) {
      // nobody awaits this; a discovery failure surfaces at the next call that has a caller
      void checkToken().catch(() => undefined)
    }
  }

  let teardowns: Array<() => void> = []

  const start = () => {
    if (teardowns.length) return
    // the watchers fire only on change, so a storageKey set while inert must be reconciled first
    storage.rekey(storageKey())
    teardowns = [
      storage.listen(),
      watchStore(configStore, storageKey, key => storage.rekey(key)),
      watchStore(configStore, config, revalidate),
      watchStore(storage.store, rawAccessToken, revalidate)
    ]
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
