import {
  computed,
  DestroyRef,
  type EnvironmentProviders,
  InjectionToken,
  inject,
  makeEnvironmentProviders,
  type Signal
} from '@angular/core'
import { createOAuth, type OAuthConfig, tokenState } from '@oidcraft/client'
import type { OAuthFetch, OAuthStatus, OAuthToken, OAuthType, OAuthTypeConfig, UserInfo } from '@oidcraft/core'
import { storeSignal, writableStoreSignal } from './signals'

export const OAUTH_CONFIG = new InjectionToken<OAuthConfig>('OAUTH_CONFIG', { providedIn: 'root', factory: () => ({}) })

/**
 * Registers the configuration the root `OAUTH` instance is built from.
 *
 * Unlike v8 there is no module-level signal behind this. An instance belongs to the injector that
 * created it, which is what makes one per request safe on a server — a process-wide holder cannot be
 * answered correctly under concurrent SSR, and would hand one request another request's token.
 */
export const provideOAuthConfig = (cfg: OAuthConfig = {}): EnvironmentProviders =>
  makeEnvironmentProviders([{ provide: OAUTH_CONFIG, useValue: cfg }])

export interface NgxOAuth {
  token: ReturnType<typeof writableStoreSignal<unknown, OAuthToken>>
  user: Signal<UserInfo | undefined>
  state: Signal<string | undefined>
  config: Signal<Partial<OAuthTypeConfig> | undefined>
  storageKey: Signal<string>
  type: Signal<OAuthType | undefined>
  accessToken: Signal<string | undefined>
  status: Signal<OAuthStatus>
  isAuthorized: Signal<boolean>
  error: Signal<string | undefined>
  hasError: Signal<boolean>
  errorDescription: Signal<string | undefined>
  setConfig: (patch?: Partial<OAuthTypeConfig>) => void
  setStorageKey: (key: string) => void
  ignorePath: (pattern: RegExp) => void
  fetch: OAuthFetch
  authHeaders: (url?: string) => Promise<Record<string, string>>
  login: ReturnType<typeof createOAuth>['login']
  logout: ReturnType<typeof createOAuth>['logout']
  oauthCallback: (url?: string | URL) => Promise<void>
  checkToken: () => Promise<void>
  autoconfigOauth: () => Promise<void>
}

/**
 * Builds one instance. Must run in an injection context — it takes a `DestroyRef` so the
 * subscriptions stop when the injector does.
 *
 * Exported rather than inlined into the token below so a child injector can hold its own instance,
 * and so this is reachable from a test without a TestBed.
 */
export const createNgxOAuth = (cfg: OAuthConfig = {}): NgxOAuth => {
  {
    // inert until the signals below exist, so nothing can fire into them mid-construction
    const core = createOAuth({ ...cfg, autoStart: false })

    const token = writableStoreSignal(core.tokenStore, core.token, core.setToken)
    const user = storeSignal(core.userStore, core.user)
    const state = storeSignal(core.stateStore, core.state)
    const config = storeSignal(core.configStore, core.config)
    const storageKey = storeSignal(core.configStore, core.storageKey)

    // one derivation for all seven, from the same pure function the other bindings use, so what a
    // template renders and what `core.status()` answers cannot disagree
    const derived = computed(() => tokenState(token()))

    inject(DestroyRef).onDestroy(() => core.dispose())
    core.start()

    return {
      token,
      user,
      state,
      config,
      storageKey,
      type: computed(() => derived().type),
      accessToken: computed(() => derived().accessToken),
      status: computed(() => derived().status),
      isAuthorized: computed(() => derived().isAuthorized),
      error: computed(() => derived().error),
      hasError: computed(() => derived().hasError),
      errorDescription: computed(() => derived().errorDescription),
      setConfig: core.setConfig,
      setStorageKey: core.setStorageKey,
      ignorePath: core.ignorePath,
      fetch: core.fetch,
      authHeaders: core.authHeaders,
      login: core.login,
      logout: core.logout,
      oauthCallback: core.oauthCallback,
      checkToken: core.checkToken,
      autoconfigOauth: core.autoconfigOauth
    }
  }
}

export const OAUTH = new InjectionToken<NgxOAuth>('OAUTH', {
  providedIn: 'root',
  factory: () => createNgxOAuth(inject(OAUTH_CONFIG))
})

/** Kept from v8 so `inject(OAUTH_FETCH)` still resolves the instance's authorized transport. */
export const OAUTH_FETCH = new InjectionToken<OAuthFetch>('OAUTH_FETCH', {
  providedIn: 'root',
  factory: () => inject(OAUTH).fetch
})

/** v8 resolved a `resource<UserInfo>`; the profile is now derived by the shared runtime, so this is
 * the signal it maintains. `undefined` until there is a session to describe. */
export const OAUTH_USER = new InjectionToken<Signal<UserInfo | undefined>>('OAUTH_USER', {
  providedIn: 'root',
  factory: () => inject(OAUTH).user
})
