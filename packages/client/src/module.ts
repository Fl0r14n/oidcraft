import { defaultOAuthFunctions } from '@oidcraft/core'
import { createConfig } from './config'
import { createFetch } from './fetch'
import { createFlows } from './flows'
import { createJwt } from './jwt'
import { createToken } from './token'
import type { OAuthConfig } from './types'
import { createUser } from './user'

/** One isolated instance: its own config, token storage and subscriptions. On a server, one per request, then `dispose()`. */
// not generic: an inferred type parameter would accept a typo'd key as an extra; annotate `OAuthConfig<TExtra>` instead
export const createOAuth = (cfg?: OAuthConfig) => {
  const configContext = createConfig(cfg)
  const functions = { ...defaultOAuthFunctions, ...cfg?.functions }
  const jwt = createJwt(configContext)
  const tokenContext = createToken(configContext, functions, cfg?.discovery)
  const fetchContext = createFetch(configContext, tokenContext)
  const flows = createFlows(configContext, tokenContext, functions, jwt)
  const userContext = createUser(configContext, tokenContext, fetchContext, functions, jwt)

  // not spread: two contexts carry their own `start`/`dispose`, and a spread would let the last one win
  const { configStore, oauthConfig, setOAuthConfig, config, setConfig, ignorePath, isPathIgnored, storageKey, setStorageKey, strictJwt } =
    configContext
  const { tokenStore, token, setToken, type, accessToken, status, isAuthorized, error, hasError, errorDescription } = tokenContext
  const { autoconfigOauth, checkToken } = tokenContext
  const { stateStore, state, login, logout, oauthCallback } = flows

  const oauth = {
    start: () => {
      tokenContext.start()
      userContext.start()
    },
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
    authHeaders: fetchContext.authHeaders,
    onUnauthorized: fetchContext.onUnauthorized
  }

  if (cfg?.autoStart !== false) {
    oauth.start()
  }
  return oauth
}

export type OAuth = ReturnType<typeof createOAuth>
