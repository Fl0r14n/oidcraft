import { defaultOAuthFunctions } from '@oidcraft/core'
import { createConfig } from './config'
import { createFetch } from './fetch'
import { createFlows } from './flows'
import { createJwt } from './jwt'
import { createToken } from './token'
import type { OAuthConfig } from './types'
import { createUser } from './user'

/**
 * One fully isolated instance: its own config, token storage and subscriptions. Create one per
 * request on a server and `dispose()` it when the render is done.
 *
 * There is deliberately no module-level pointer to "the current instance" — it could not be answered
 * correctly under concurrent SSR, and every consumer already holds one, through its framework's
 * injection or through the value this returns.
 */
// Not generic in the config's extra fields: a type parameter here would be *inferred* from the
// argument, so `createOAuth({ storagekey: 'token' })` would take the typo for a legitimate extra and
// compile. Annotate instead — `const cfg: OAuthConfig<{ tenant: string }> = …`.
export const createOAuth = (cfg?: OAuthConfig) => {
  const configContext = createConfig(cfg)
  const functions = { ...defaultOAuthFunctions, ...cfg?.functions }
  const jwt = createJwt(configContext)
  const tokenContext = createToken(configContext, functions, cfg?.discovery)
  const fetchContext = createFetch(configContext, tokenContext)
  const flows = createFlows(configContext, tokenContext, functions, jwt)
  const userContext = createUser(configContext, tokenContext, fetchContext, functions, jwt)

  // Assembled member by member rather than by spreading the contexts: two of them carry their own
  // `start`/`dispose`, and a spread would silently let the last one win over the pair below.
  const { configStore, oauthConfig, setOAuthConfig, config, setConfig, ignorePath, isPathIgnored, storageKey, setStorageKey, strictJwt } =
    configContext
  const { tokenStore, token, setToken, type, accessToken, status, isAuthorized, error, hasError, errorDescription } = tokenContext
  const { autoconfigOauth, checkToken } = tokenContext
  const { stateStore, state, login, logout, oauthCallback } = flows

  const oauth = {
    // idempotent, and re-armable after a dispose
    start: () => {
      tokenContext.start()
      userContext.start()
    },
    // idempotent: the teardowns are Set deletes, so a double dispose is harmless
    dispose: () => {
      tokenContext.dispose()
      userContext.dispose()
    },
    configStore,
    oauthConfig,
    setOAuthConfig,
    config,
    setConfig,
    ignorePath,
    isPathIgnored,
    storageKey,
    setStorageKey,
    strictJwt,
    tokenStore,
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
    stateStore,
    state,
    login,
    logout,
    oauthCallback,
    userStore: userContext.userStore,
    user: userContext.user,
    functions,
    jwt,
    fetch: fetchContext.oauthFetch,
    authHeaders: fetchContext.authHeaders
  }

  // Construction is inert — no subscriptions, no network — because an instance is normally built at
  // module scope, where a side effect runs on import: before a test can install its mocks, and during
  // an SSR pass that may only need the type.
  if (cfg?.autoStart !== false) {
    oauth.start()
  }
  return oauth
}

export type OAuth = ReturnType<typeof createOAuth>
