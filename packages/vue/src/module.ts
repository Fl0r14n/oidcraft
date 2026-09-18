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

export const oauthKey: InjectionKey<OAuth> = Symbol('vue-oidc')

export const getActiveOAuth = (): OAuth => {
  const instance = hasInjectionContext() && inject(oauthKey, undefined)
  if (!instance) {
    throw new Error(
      '[vue-oidc]: no OAuth instance in this injection context. Install one with app.use(createOAuth()) and resolve it inside a component/store setup, a navigation guard (before the first await), or app.runWithContext(). Outside a context, hold the instance createOAuth() returned.'
    )
  }
  return instance
}

export const createOAuth = (cfg?: OAuthConfig): OAuth => {
  // inert until the scope is running, so the refs below exist before anything can fire into them
  const core = createCoreOAuth({ ...cfg, autoStart: false })
  const scope = effectScope(true)
  return scope.run(() => {
    const token = writableStoreRef(core.tokenStore, core.token, core.setToken)
    const config = writableStoreRef(core.configStore, core.oauthConfig, core.setOAuthConfig)
    const typeConfig = writableStoreRef(core.configStore, core.config, core.setConfig)
    const storageKey = writableStoreRef(core.configStore, core.storageKey, core.setStorageKey)
    const user = storeRef(core.userStore, core.user)
    const state = storeRef(core.stateStore, core.state)

    // one derivation for all seven, from the same pure function the other bindings use, so what Vue
    // renders and what `core.status()` answers cannot disagree
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
    // a freshly created detached scope is always active, so run() cannot return undefined here
  }) as OAuth
}

/**
 * Stops the instance installed in `app`.
 *
 * `createOAuth` opens a **detached** effect scope, so the subscriptions it holds — the refresh
 * watcher, the user watchers, the cross-tab storage listener — are owned by no component and nothing
 * stops them for you. On the client that is what you want: one instance, alive as long as the page.
 *
 * Under SSR it is the opposite. One instance per request keeps requests isolated, and a render that
 * never disposes leaks that request's subscriptions and its token graph for the lifetime of the
 * process. Call this in a `finally`, so a render that throws still cleans up:
 *
 * ```ts
 * try {
 *   return await renderToString(app)
 * } finally {
 *   disposeOAuth(app)
 * }
 * ```
 *
 * This is the only reason to reach an instance through an app rather than holding what `createOAuth()`
 * returned, which is why it exists as a named operation.
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
  login: (parameters?: OAuthParameters, options?: RedirectOptions) => Promise<string | undefined | void>
  logout: (logoutRedirectUri?: string, state?: string, options?: RedirectOptions) => Promise<string | undefined>
  oauthCallback: (url?: string | URL) => Promise<void>
  checkToken: () => Promise<void>
  autoconfigOauth: () => Promise<void>
}
