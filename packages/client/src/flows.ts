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
  type AuthorizationHandoff,
  type AuthorizationResult,
  assertSecure,
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

const CALLBACK_PARAMETERS = ['code', 'state', 'iss', 'session_state', 'id_token', 'error', 'error_description', 'error_uri']

const REVOCATION_PATIENCE = 3_000

const isAddressBar = (source: string | URL | Location) =>
  source === globalThis.location || (globalThis.location !== undefined && String(source) === globalThis.location.href)

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

/** Long enough to sign in, short enough that an abandoned sign-in's verifier does not linger. */
const HANDOFF_TTL = 10 * 60_000

export const createFlows = (
  { config, storageKey }: Pick<ConfigContext, 'config' | 'storageKey'>,
  { token, setToken, autoconfigOauth }: Pick<TokenContext, 'token' | 'setToken' | 'autoconfigOauth'>,
  functions: OAuthFunctions,
  jwt: Jwt
) => {
  // Keyed by its own state, never in the shared token: written there, starting a login signed every other tab out. Any tab
  // may finish it — a callback can land in a new tab or window — and an abandoned one expires.
  const handoffPrefix = () => `${storageKey()}.handoff.`
  let pending: Partial<AuthorizationHandoff> | undefined
  const saveHandoff = (handoff: Partial<AuthorizationHandoff>) => {
    pending = handoff
    try {
      const store = globalThis.localStorage
      if (!store || !handoff.state) return
      for (let i = store.length - 1; i >= 0; i--) {
        const key = store.key(i)
        if (key?.startsWith(handoffPrefix()) && !(Number(JSON.parse(store.getItem(key) ?? '{}').expires) > Date.now()))
          store.removeItem(key)
      }
      store.setItem(`${handoffPrefix()}${handoff.state}`, JSON.stringify({ ...handoff, expires: Date.now() + HANDOFF_TTL }))
    } catch {}
  }
  const takeHandoff = (state: string | undefined): Partial<AuthorizationHandoff> | undefined => {
    let stored: Partial<AuthorizationHandoff> | undefined
    try {
      const store = globalThis.localStorage
      // An error answered without its state, as RFC 6749 §4.1.2.1 forbids but servers do, is matched only when one is pending.
      const keys = Array.from({ length: store?.length ?? 0 }, (_, i) => store?.key(i)).filter(key => key?.startsWith(handoffPrefix()))
      const key = state ? `${handoffPrefix()}${state}` : keys.length === 1 ? keys[0] : undefined
      if (key) {
        const raw = globalThis.localStorage?.getItem(key)
        globalThis.localStorage?.removeItem(key)
        const { expires, ...handoff } = raw ? JSON.parse(raw) : { expires: 0 }
        if (Number(expires) > Date.now()) stored = handoff
      }
    } catch {}
    const handoff = stored ?? (state === undefined || pending?.state === state ? pending : undefined)
    pending = undefined
    return handoff
  }

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
    saveHandoff(handoff)
    // a dead session's error is not carried into the new attempt; a live session stays until the callback replaces it
    if (token().error) setToken({})
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
      assertSecure(logoutPath, (config() as OpenIdConfig)?.allowInsecure)
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
    // a revocation that hangs or fails never keeps the person signed in
    await settledWithin(REVOCATION_PATIENCE, () => functions.revoke(token(), config()))
    setToken({})
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
      const result = await completeAuthorization(config(), source as never, takeHandoff(parameters.state), {
        functions,
        verifyIdToken: jwt
      })
      // A callback that failed, or that nobody started, never ends a live session: it is reported only to one with none.
      if (result?.ok) setToken(result.token)
      else if (result && !token()?.access_token) setToken(failureState(result))
    } finally {
      // after the exchange, not before: a live Location is read again inside it
      // a URL handed in is cleaned too when it is the address bar's, as a router passing `location.href` does
      if (flow !== 'none' && isAddressBar(source)) forgetCallback(flow)
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
