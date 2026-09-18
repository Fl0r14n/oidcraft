import { useMemo, useSyncExternalStore } from 'react'
import {
  isExpiredToken,
  type OAuth,
  type OAuthConfig,
  type OAuthStatus,
  type OAuthToken,
  type OAuthType,
  type OAuthTypeConfig,
  type Subscribable,
  tokenState,
  type UserInfo
} from 'react-oauth-oidc/core'
import { useOAuthInstance } from './provider'

export const useStoreValue = <S, T>(store: Subscribable<S>, selector: (state: S) => T, serverSelector?: (state: S) => T): T => {
  const snapshot = () => selector(store.getState())
  const serverSnapshot = serverSelector ? () => serverSelector(store.getState()) : snapshot
  return useSyncExternalStore(store.subscribe, snapshot, serverSnapshot)
}

const SERVER_TOKEN: OAuthToken = Object.freeze({})
const serverToken = () => SERVER_TOKEN
// the user is derived from the id_token, and `fetchUser` is async — neither resolves during a server pass
const serverUser = () => undefined

export const useOAuthSelector = <T>(selector: (token: OAuthToken) => T): T =>
  useStoreValue(
    useOAuthInstance().tokenStore,
    state => selector(state.value),
    () => selector(SERVER_TOKEN)
  )

export const useIsAuthorized = (): boolean => useOAuthSelector(token => tokenState(token).isAuthorized)
export const useOAuthStatus = (): OAuthStatus => useOAuthSelector(token => tokenState(token).status)
export const useAccessToken = (): string | undefined => useOAuthSelector(token => tokenState(token).accessToken)
export const useOAuthError = (): string | undefined => useOAuthSelector(token => tokenState(token).errorDescription)

export interface OAuthActions {
  login: OAuth['login']
  logout: OAuth['logout']
  oauthCallback: OAuth['oauthCallback']
  setToken: OAuth['setToken']
  setConfig: OAuth['setConfig']
  setStorageKey: OAuth['setStorageKey']
  ignorePath: OAuth['ignorePath']
  autoconfigOauth: OAuth['autoconfigOauth']
  checkToken: OAuth['checkToken']
}

export const useOAuthActions = (): OAuthActions => {
  const oauth = useOAuthInstance()
  return useMemo(
    () => ({
      login: oauth.login,
      logout: oauth.logout,
      oauthCallback: oauth.oauthCallback,
      setToken: oauth.setToken,
      setConfig: oauth.setConfig,
      setStorageKey: oauth.setStorageKey,
      ignorePath: oauth.ignorePath,
      autoconfigOauth: oauth.autoconfigOauth,
      checkToken: oauth.checkToken
    }),
    [oauth]
  )
}

export const useOAuthToken = (): [OAuthToken, OAuth['setToken']] => {
  const { tokenStore, setToken } = useOAuthInstance()
  return [useStoreValue(tokenStore, state => state.value, serverToken), setToken]
}

export const useOAuthUser = (): UserInfo | undefined => useStoreValue(useOAuthInstance().userStore, state => state.user, serverUser)

export const useOAuthConfig = () => {
  const { configStore, setOAuthConfig, setConfig, setStorageKey, ignorePath } = useOAuthInstance()
  const oauthConfig = useStoreValue(configStore, state => state.oauthConfig)
  return {
    oauthConfig,
    config: oauthConfig.config as Partial<OAuthTypeConfig> | undefined,
    storageKey: oauthConfig.storageKey || 'token',
    set: setOAuthConfig as (config: Partial<OAuthConfig>) => void,
    setConfig,
    setStorageKey,
    ignorePath
  }
}

export const useOAuthFetch = () => useOAuthInstance().fetch

export const useOAuthAuthHeaders = () => useOAuthInstance().authHeaders

export const useOAuthFunctions = () => useOAuthInstance().functions

export interface OAuthState {
  type: OAuthType | undefined
  accessToken: string | undefined
  status: OAuthStatus
  isAuthorized: boolean
  error: string | undefined
  hasError: boolean
  errorDescription: string | undefined
  /** the `state` parameter echoed back by the last authorization redirect */
  state: string | undefined
  config: Partial<OAuthTypeConfig> | undefined
  storageKey: string
  setConfig: OAuth['setConfig']
  setStorageKey: OAuth['setStorageKey']
  ignorePath: OAuth['ignorePath']
  login: OAuth['login']
  logout: OAuth['logout']
  oauthCallback: OAuth['oauthCallback']
  autoconfigOauth: OAuth['autoconfigOauth']
  isExpiredToken: typeof isExpiredToken
}

export const useOAuth = (): OAuthState => {
  const oauth = useOAuthInstance()
  const token = useStoreValue(oauth.tokenStore, state => state.value, serverToken)
  const oauthConfig = useStoreValue(oauth.configStore, state => state.oauthConfig)
  const echoedState = useStoreValue(oauth.stateStore, state => state.state)

  return {
    ...tokenState(token),
    state: echoedState,
    config: oauthConfig.config as Partial<OAuthTypeConfig> | undefined,
    storageKey: oauthConfig.storageKey || 'token',
    setConfig: oauth.setConfig,
    setStorageKey: oauth.setStorageKey,
    ignorePath: oauth.ignorePath,
    login: oauth.login,
    logout: oauth.logout,
    oauthCallback: oauth.oauthCallback,
    autoconfigOauth: oauth.autoconfigOauth,
    isExpiredToken
  }
}

export interface Auth {
  isLoggedIn: boolean
  token: OAuthToken
  user?: UserInfo | undefined
  error?: string | undefined
  login: OAuth['login']
  logout: OAuth['logout']
}

export const useAuth = (): Auth => {
  const oauth = useOAuthInstance()
  const token = useStoreValue(oauth.tokenStore, state => state.value, serverToken)
  const user = useStoreValue(oauth.userStore, state => state.user, serverUser)
  const { isAuthorized, errorDescription } = tokenState(token)

  return {
    isLoggedIn: isAuthorized,
    token,
    user,
    error: errorDescription,
    login: oauth.login,
    logout: oauth.logout
  }
}
