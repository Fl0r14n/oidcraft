import type {
  AuthorizationCodeParameters,
  ClientCredentialConfig,
  OAuthFunctions,
  OAuthParameters,
  OpenIdConfig,
  ResourceOwnerConfig,
  ResourceOwnerParameters
} from '@oidcraft/core'
import { beginAuthorization, completeAuthorization, parseRedirectParameters } from '@oidcraft/core'
import type { ConfigContext } from './config'
import type { Jwt } from './jwt'
import { createStore } from './store'
import type { TokenContext } from './token'
import type { RedirectOptions } from './types'

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
    // persisted before the navigation, and by itself — the handoff is the whole of what has to
    // survive the round trip, and anything left over from a previous attempt is not part of it
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

  const runCallback = async (source: string | URL | Location) => {
    const { flow, parameters } = parseRedirectParameters(source as never)
    setState(parameters.state)
    if (flow === 'code') {
      await autoconfigOauth()
    }
    // the handoff is read from the token, which is where `toAuthorizationUrl` left it. State, nonce,
    // PKCE and the RFC 9207 `iss` are all checked inside completeAuthorization.
    const result = await completeAuthorization(config(), source as never, token(), { functions, verifyIdToken: jwt })
    if (result) {
      setToken(result)
    }
  }

  const inFlight = new Map<string, Promise<void>>()

  const oauthCallback = async (url?: string | URL) => {
    // never on the server: the verifier that has to match this code is in the user's browser storage
    if (typeof window === 'undefined') return
    const source = (url && new URL(url)) || globalThis.location
    if (!source) return
    const { flow } = parseRedirectParameters(source as never)
    if (flow === 'none') return

    // Keyed on the redirect itself, and kept for the life of the instance rather than for the life
    // of the request. A component mounting twice is only half of it: a browser Back into the callback
    // url would otherwise re-exchange a code the IdP has already consumed, and that does not fail
    // harmlessly — the `invalid_grant` lands in the token and ends a session that was working.
    const key = `${source.search || ''}${source.hash || ''}`
    const existing = inFlight.get(key)
    if (existing) return existing

    // registered before the first await, so a synchronous second call sees it
    const run = runCallback(source)
    inFlight.set(key, run)
    return run
  }

  return { stateStore, state, login, logout, oauthCallback }
}

export type FlowsContext = ReturnType<typeof createFlows>
