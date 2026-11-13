import type { RedirectOptions } from '@oidcraft/client'
import { createOAuth as createCoreOAuth, isExpiredToken, type OAuthConfig, tokenState } from '@oidcraft/client'
import type {
  OAuthFetch,
  OAuthFunctions,
  OAuthParameters,
  OAuthStatus,
  OAuthToken,
  OAuthType,
  OAuthTypeConfig,
  UserInfo
} from '@oidcraft/core'
import {
  type App,
  type ComputedRef,
  computed,
  effectScope,
  hasInjectionContext,
  type InjectionKey,
  inject,
  onScopeDispose,
  type Ref,
  type WritableComputedRef
} from 'vue'
import { storeRef, writableStoreRef } from './refs'

export const oauthKey: InjectionKey<OAuth> = Symbol('@oidcraft/vue')

export const getActiveOAuth = (): OAuth => {
  const instance = hasInjectionContext() && inject(oauthKey, undefined)
  if (!instance) {
    throw new Error(
      '[@oidcraft/vue]: no OAuth instance in this injection context. Install one with app.use(createOAuth()) and resolve it inside a component/store setup, a navigation guard (before the first await), or app.runWithContext(). Outside a context, hold the instance createOAuth() returned.'
    )
  }
  return instance
}

export const createOAuth = (cfg?: OAuthConfig): OAuth => {
  // inert until the scope runs, so the refs exist before anything fires into them
  const core = createCoreOAuth({ ...cfg, autoStart: false })
  const scope = effectScope(true)
  return scope.run(() => {
    const token = writableStoreRef(core.tokenStore, core.token, core.setToken)
    const config = writableStoreRef(core.configStore, core.oauthConfig, core.setOAuthConfig)
    const typeConfig = writableStoreRef(core.configStore, core.config, core.setConfig)
    const storageKey = writableStoreRef(core.configStore, core.storageKey, core.setStorageKey)
    const user = storeRef(core.userStore, core.user)
    const state = storeRef(core.stateStore, core.state)

    const derived = computed(() => tokenState(token.value))

    onScopeDispose(() => core.dispose())
    core.start()

    const oauth: OAuth = {
      install: (app: App) => {
        app.provide(oauthKey, oauth)
        app.provide('fetch', core.fetch)
        app.provide('login', core.login)
        app.provide('logout', core.logout)
        app.provide('oauth-callback', core.oauthCallback)
      },
      dispose: () => scope.stop(),
      config,
      typeConfig,
      storageKey,
      ignorePath: core.ignorePath,
      functions: core.functions,
      fetch: core.fetch,
      authHeaders: core.authHeaders,
      onUnauthorized: core.onUnauthorized,
      token,
      user,
      state,
      type: computed(() => derived.value.type),
      accessToken: computed(() => derived.value.accessToken),
      status: computed(() => derived.value.status),
      isAuthorized: computed(() => derived.value.isAuthorized),
      error: computed(() => derived.value.error),
      hasError: computed(() => derived.value.hasError),
      errorDescription: computed(() => derived.value.errorDescription),
      login: core.login,
      logout: core.logout,
      oauthCallback: core.oauthCallback,
      checkToken: core.checkToken,
      autoconfigOauth: core.autoconfigOauth
    }
    return oauth
  }) as OAuth
}

/**
 * Stops the instance installed in `app`. Its effect scope is detached, so nothing else stops it: under SSR, call this
 * in a `finally` after each render.
 */
export const disposeOAuth = (app: App) => {
  app.runWithContext(() => getActiveOAuth()).dispose()
}

export const useOAuthConfig = () => getActiveOAuth().config
export const useOAuthFunctions = () => getActiveOAuth().functions
export const useOAuthToken = () => getActiveOAuth().token
export const useOAuthUser = () => getActiveOAuth().user
export const useOAuthFetch = () => getActiveOAuth().fetch
export const useOAuth = () => {
  const {
    typeConfig,
    storageKey,
    ignorePath,
    type,
    accessToken,
    status,
    isAuthorized,
    error,
    hasError,
    errorDescription,
    state,
    login,
    logout,
    oauthCallback,
    autoconfigOauth,
    checkToken
  } = getActiveOAuth()
  return {
    config: typeConfig,
    storageKey,
    ignorePath,
    type,
    accessToken,
    status,
    isAuthorized,
    error,
    hasError,
    errorDescription,
    state,
    login,
    logout,
    oauthCallback,
    isExpiredToken,
    autoconfigOauth,
    checkToken
  }
}

export interface OAuth {
  install: (app: App) => void
  /** stops this instance's subscriptions — call it when a server render ends */
  dispose: () => void
  config: WritableComputedRef<OAuthConfig>
  /** the provider/endpoint part of the config (`config.value.config`) */
  typeConfig: WritableComputedRef<Partial<OAuthTypeConfig> | undefined>
  storageKey: WritableComputedRef<string>
  /** register a path the authorization interceptor must skip — idempotent */
  ignorePath: (pattern: RegExp) => void
  functions: OAuthFunctions
  fetch: OAuthFetch
  authHeaders: (url?: string) => Promise<Record<string, string>>
  /** a 401 at `url`: ends the token when it went there, keeping only the body's error (FR-L6) */
  onUnauthorized: (url: string | undefined, body: unknown) => void
  token: WritableComputedRef<OAuthToken>
  user: Ref<UserInfo | undefined>
  state: Ref<string | undefined>
  type: ComputedRef<OAuthType | undefined>
  accessToken: ComputedRef<string | undefined>
  status: ComputedRef<OAuthStatus>
  isAuthorized: ComputedRef<boolean>
  error: ComputedRef<string | undefined>
  hasError: ComputedRef<boolean>
  errorDescription: ComputedRef<string | undefined>
  login: (parameters?: OAuthParameters, options?: RedirectOptions) => Promise<string | undefined>
  logout: (logoutRedirectUri?: string, state?: string, options?: RedirectOptions) => Promise<string | undefined>
  oauthCallback: (url?: string | URL) => Promise<void>
  checkToken: () => Promise<void>
  autoconfigOauth: () => Promise<void>
}
