import type {
  AuthorizationCodeParameters,
  ClientCredentialConfig,
  OAuthFunctions,
  OAuthParameters,
  OpenIdConfig,
  ResourceOwnerConfig,
  ResourceOwnerParameters
} from '@oidcraft/core'
import {
  type AuthorizationResult,
  beginAuthorization,
  completeAuthorization,
  type OAuthToken,
  parseRedirectParameters
} from '@oidcraft/core'
import type { ConfigContext } from './config'
import type { Jwt } from './jwt'
import { createStore } from './store'
import type { TokenContext } from './token'
import type { RedirectOptions } from './types'

const CALLBACK_PARAMETERS = ['code', 'state', 'iss', 'session_state', 'error', 'error_description', 'error_uri']

const REVOCATION_PATIENCE = 3_000

const settledWithin = async (ms: number, task: () => unknown) => {
  let timer: ReturnType<typeof setTimeout> | undefined
  const elapsed = new Promise<void>(resolve => {
    timer = setTimeout(resolve, ms)
  })
  const settled = Promise.resolve()
    .then(task)
    .then(
      () => undefined,
      () => undefined
    )
  await Promise.race([settled, elapsed])
  clearTimeout(timer)
}

// FR-L6: a callback that ended without a token becomes the token state.
const failureState = (failure: Exclude<AuthorizationResult, { ok: true }>): OAuthToken => {
  if (failure.reason === 'refused') {
    return { error: failure.error, ...(failure.errorDescription && { error_description: failure.errorDescription }) }
  }
  if (failure.reason === 'invalid') return { error: failure.message }
  return { error: 'temporarily_unavailable', error_description: 'the token endpoint did not answer' }
}

export const createFlows = (
  { config }: Pick<ConfigContext, 'config'>,
  { token, setToken, autoconfigOauth }: Pick<TokenContext, 'token' | 'setToken' | 'autoconfigOauth'>,
  functions: OAuthFunctions,
  jwt: Jwt
) => {
  const stateStore = createStore<{ state?: string | undefined }>({})
  const state = () => stateStore.getState().state
  const setState = (value?: string) => stateStore.setState({ state: value })

  const toAuthorizationUrl = async (parameters: AuthorizationCodeParameters, redirect: boolean) => {
    if (!(config() as OpenIdConfig)?.authorizePath) {
      throw new Error(
        'cannot start the authorization flow: no authorizePath. Set it, or set issuerPath so autoconfigOauth() can discover it — and check that the discovery request succeeded.'
      )
    }
    const { url, handoff } = await beginAuthorization(config(), parameters, { functions })
    // persisted before the navigation, replacing any previous attempt's state
    setToken(handoff)
    if (redirect) {
      globalThis.location?.replace(url)
    }
    return url
  }

  const login = async (parameters?: OAuthParameters, { redirect = true }: RedirectOptions = {}) => {
    await autoconfigOauth()
    if (parameters && (parameters as ResourceOwnerParameters).password) {
      setToken((await functions.resourceOwnerLogin(parameters as ResourceOwnerParameters, config() as ResourceOwnerConfig)) || {})
    } else if (
      parameters &&
      (parameters as AuthorizationCodeParameters).redirectUri &&
      (parameters as AuthorizationCodeParameters).responseType
    ) {
      return await toAuthorizationUrl(parameters as AuthorizationCodeParameters, redirect)
    } else {
      setToken((await functions.clientCredentialLogin(config() as ClientCredentialConfig)) || {})
    }
  }

  const logout = async (logoutRedirectUri?: string, logoutState?: string, { redirect = true }: RedirectOptions = {}) => {
    await autoconfigOauth()
    const { logoutPath, clientId, logoutRedirectUri: configLogoutRedirectUri } = (config() as OpenIdConfig) || {}
    const returnUri = logoutRedirectUri || configLogoutRedirectUri
    if (returnUri && logoutPath) {
      const { id_token } = token()
      const params = new URLSearchParams({ post_logout_redirect_uri: returnUri })
      if (clientId) params.set('client_id', clientId)
      if (id_token) params.set('id_token_hint', id_token)
      if (logoutState) params.set('state', logoutState)
      // revoked first, as ending the session leaves an offline refresh token working; a failing revocation never blocks sign-out
      await settledWithin(REVOCATION_PATIENCE, () => functions.revoke(token(), config()))
      setToken({})
      const url = `${logoutPath}${logoutPath.includes('?') ? '&' : '?'}${params}`
      if (redirect) {
        globalThis.location?.replace(url)
      }
      return url
    }
    try {
      await functions.revoke(token(), config())
    } finally {
      setToken({})
    }
    return undefined
  }

  const forgetCallback = (flow: 'code' | 'implicit') => {
    const url = new URL(globalThis.location.href)
    for (const name of CALLBACK_PARAMETERS) url.searchParams.delete(name)
    const fragment = new URLSearchParams(url.hash.slice(1))
    for (const name of CALLBACK_PARAMETERS) fragment.delete(name)
    url.hash = flow === 'implicit' ? '' : fragment.toString()
    globalThis.history?.replaceState(globalThis.history.state, '', url.toString())
  }

  const runCallback = async (source: string | URL | Location) => {
    const { flow, parameters } = parseRedirectParameters(source as never)
    setState(parameters.state)
    try {
      // an implicit callback after a reload still needs the discovered `jwks_uri` to verify its ID token
      await autoconfigOauth()
      const result = await completeAuthorization(config(), source as never, token(), { functions, verifyIdToken: jwt })
      if (result) {
        setToken(result.ok ? result.token : failureState(result))
      }
    } finally {
      // after the exchange, not before: a live Location is read again inside it
      if (source === globalThis.location && flow !== 'none') forgetCallback(flow)
    }
  }

  const inFlight = new Map<string, Promise<void>>()

  const oauthCallback = async (url?: string | URL) => {
    // never on the server: the handoff this code must match is in the browser's storage
    if (typeof window === 'undefined') return
    const source = (url && new URL(url)) || globalThis.location
    if (!source) return
    const { flow } = parseRedirectParameters(source as never)
    if (flow === 'none') return

    // kept for the instance's life: a Back into the callback would re-exchange a spent code and end a working session
    const key = `${source.search || ''}${source.hash || ''}`
    const existing = inFlight.get(key)
    if (existing) return existing

    const run = runCallback(source)
    inFlight.set(key, run)
    return run
  }

  return { stateStore, state, login, logout, oauthCallback }
}

export type FlowsContext = ReturnType<typeof createFlows>
