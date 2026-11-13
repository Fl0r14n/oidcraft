import {
  type AuthorizationResult,
  applyDiscovery,
  beginAuthorization,
  type CallbackCheck,
  completeAuthorization,
  constantTimeEquals,
  createDiscovery,
  createIdTokenVerifier,
  defaultOAuthFunctions,
  type IdTokenVerifier,
  type OAuthToken,
  type OpenIdConfig,
  randomString,
  sha256
} from '@oidcraft/core'
import type { BrokeringAdapter, Session } from '@oidcraft/provider'
import { DEFAULT_TTL, OAuthError, type SelectionHints, selectUpstream } from '@oidcraft/provider'
import { base64url } from 'jose'
import { pickClaims } from './claims'
import { logoutHintId } from './logout'
import type { BrokerCallback, BrokeredIdentity, Handoff, UpstreamProvider } from './types'

// OIDC Core §5.4: scope claims come from UserInfo, and one whose `sub` differs from the ID token's is not used (§5.3.4).
const userInfoOf = async (resolved: OpenIdConfig, token: OAuthToken | undefined, subject: string) => {
  if (!resolved.userPath || !token?.access_token) return {}
  const bearer = (input: string | URL | Request, init?: RequestInit) =>
    fetch(input, { ...init, headers: { ...init?.headers, Authorization: `Bearer ${token.access_token}` } })
  const info = await defaultOAuthFunctions.userInfo(resolved, bearer).catch(() => undefined)
  return info?.sub === subject ? info : {}
}

export type BrokerConfig = {
  adapter: BrokeringAdapter
  providers: UpstreamProvider[]
  /** Where the upstream sends the browser back. Register it with every upstream. */
  callbackUri: string
  /**
   * Where an upstream sends the browser back after signing it out (FR-F8). Registered with every
   * upstream that has `propagateLogout`; the host's route there calls `completeLogout`.
   */
  postLogoutRedirectUri?: string
  /** Pass `provider.config.ttl.session`: an upstream ID token kept as a logout hint lives as long as that session (FR-F8, FR-F10). */
  sessionTtl?: number
  /** Seconds a single-use handoff stays usable (FR-F3). */
  handoffTtl?: number
  /** Development only: lets discovery and the token exchange run over http. */
  allowInsecure?: boolean
}

const DEFAULT_HANDOFF_TTL = 600

// Every check the RP core makes before believing a callback (FR-L2) maps to its own downstream error.
const CHECKS: Record<CallbackCheck, { description: string; spec: string }> = {
  state: { description: 'the upstream callback did not match the handoff that started it', spec: 'RFC 6749 §10.12' },
  issuer: {
    description: 'the upstream callback did not name the authorization server it was sent to',
    spec: 'RFC 9207 §2.4'
  },
  nonce: { description: 'the upstream ID token did not carry the nonce it was asked for', spec: 'FR-F3' },
  id_token: { description: 'the upstream ID token failed verification', spec: 'OIDC Core §3.1.3.7' }
}

const upstreamFailure = (provider: string, result: AuthorizationResult | undefined) => {
  if (!result) {
    return new OAuthError('server_error', {
      description: `the callback from ${provider} carried neither a code nor an error`,
      spec: 'FR-F11'
    })
  }
  if (result.ok) return undefined
  if (result.reason === 'unreachable') {
    return new OAuthError('temporarily_unavailable', { description: `${provider} did not answer the token request`, spec: 'FR-F11' })
  }
  if (result.reason === 'invalid') {
    const { description, spec } = CHECKS[result.check]
    return new OAuthError('access_denied', { description: `${provider}: ${description}`, spec })
  }
  const described = result.errorDescription ? `: ${result.errorDescription}` : ''
  return new OAuthError('access_denied', {
    description: `${provider} refused the request with ${result.error}${described}`,
    spec: 'FR-F11'
  })
}

// FR-F3: binds the handoff to the browser that started it, or a callback URL is a bearer credential (login CSRF).
const bindingCookie = (state: string) => `oidcraft.fed.${state}`

const cookieValue = (header: string | null | undefined, name: string) => {
  for (const pair of header?.split(';') ?? []) {
    const separator = pair.indexOf('=')
    if (separator > 0 && pair.slice(0, separator).trim() === name) return pair.slice(separator + 1).trim()
  }
  return undefined
}

const hashOf = async (value: string) => base64url.encode(await sha256(value))

export const createBroker = (config: BrokerConfig) => {
  const callback = new URL(config.callbackUri)
  const cookieFor = (state: string, value: string, maxAge: number) =>
    [
      `${bindingCookie(state)}=${value}`,
      `Path=${callback.pathname}`,
      'HttpOnly',
      // Lax, not Strict: the upstream's redirect back is a cross-site top-level navigation.
      'SameSite=Lax',
      ...(callback.protocol === 'https:' ? ['Secure'] : []),
      `Max-Age=${maxAge}`
    ].join('; ')

  // FR-F6/FR-F7 read the upstream ID token, so a provider without `openid` fails here rather than at the callback (NFR-D2).
  for (const provider of config.providers) {
    if (provider.propagateLogout && !config.postLogoutRedirectUri) {
      throw new OAuthError('server_error', {
        description: `upstream ${provider.id} propagates logout, but the broker has no postLogoutRedirectUri for it to return to`,
        spec: 'FR-F8'
      })
    }
    if (!provider.scopes.includes('openid')) {
      throw new OAuthError('server_error', {
        description: `upstream ${provider.id} is configured without the openid scope, so it will never return an ID token to broker`,
        spec: 'FR-F1'
      })
    }
  }

  // A latency cache only: no request's outcome depends on whether it is warm (FR-A1).
  const discover = createDiscovery()
  const verifiers = new Map<string, IdTokenVerifier>()

  const configurationFor = async (provider: UpstreamProvider) => {
    const base: Partial<OpenIdConfig> = {
      issuerPath: provider.issuer,
      clientId: provider.clientId,
      ...(provider.clientSecret !== undefined && { clientSecret: provider.clientSecret }),
      ...(provider.tokenEndpointAuthMethod && { tokenEndpointAuthMethod: provider.tokenEndpointAuthMethod }),
      scope: provider.scopes.join(' '),
      // FR-C3 holds upstream too: no upstream worth brokering to lacks S256.
      pkce: true,
      ...(config.allowInsecure && { allowInsecure: true })
    }
    // The endpoints below are trusted only because `applyDiscovery` checks the issuer (OIDC Discovery 1.0 §4.3).
    const resolved = applyDiscovery(base, await discover(base))
    if (!resolved.authorizePath || !resolved.tokenPath) {
      throw new OAuthError('temporarily_unavailable', {
        description: `discovery for upstream ${provider.id} at ${provider.issuer} returned no usable endpoints`,
        spec: 'FR-F11'
      })
    }
    return resolved
  }

  const verifierFor = (provider: UpstreamProvider, resolved: OpenIdConfig) => {
    let verifier = verifiers.get(provider.id)
    if (!verifier) {
      // Per provider, not per callback: jose caches the key set on the verifier.
      verifier = createIdTokenVerifier({
        jwksUri: resolved.jwksUri,
        issuer: resolved.issuer || resolved.issuerPath,
        audience: provider.clientId,
        ...(config.allowInsecure && { allowInsecure: true })
      })
      verifiers.set(provider.id, verifier)
    }
    return verifier
  }

  const providerById = (id: string) => config.providers.find(provider => provider.id === id)

  const required = (id: string) => {
    const provider = providerById(id)
    if (!provider) throw new OAuthError('server_error', { description: `unknown upstream provider ${id}`, spec: 'FR-F1' })
    return provider
  }

  return {
    providers: config.providers,

    /** Home-realm discovery (FR-F4); returns the candidates when it cannot decide alone. */
    select: (hints: SelectionHints, explicit?: string) => selectUpstream(config.providers, hints, explicit),

    /** Begins the upstream leg; the single-use handoff holds the PKCE verifier and the interaction it resumes (FR-F3). */
    async start(
      interactionId: string,
      providerId: string,
      options: { loginHint?: string; prompt?: string | string[]; uiLocales?: string | string[]; maxAge?: number; acrValues?: string[] } = {}
    ) {
      const provider = required(providerId)
      const resolved = await configurationFor(provider)

      const prompt = Array.isArray(options.prompt) ? options.prompt.join(' ') : options.prompt
      const uiLocales = Array.isArray(options.uiLocales) ? options.uiLocales.join(' ') : options.uiLocales

      const request = await beginAuthorization(resolved, {
        redirectUri: config.callbackUri,
        responseType: 'code',
        extras: {
          ...provider.authorizationParams,
          ...(options.loginHint && { login_hint: options.loginHint }),
          // FR-F9: re-authentication demands pass through rather than being met by the upstream's existing session.
          ...(prompt && { prompt }),
          ...(options.maxAge !== undefined && { max_age: String(options.maxAge) }),
          ...(options.acrValues?.length && { acr_values: options.acrValues.join(' ') }),
          ...(uiLocales && { ui_locales: uiLocales })
        }
      })

      const { state, nonce, code_verifier } = request.handoff
      if (!state || !nonce || !code_verifier) {
        throw new OAuthError('server_error', {
          description: 'the authorization request produced no state, nonce or PKCE verifier',
          spec: 'FR-F3'
        })
      }

      const ttl = config.handoffTtl ?? DEFAULT_HANDOFF_TTL
      const binding = randomString()
      const expiresAt = new Date(Date.now() + ttl * 1000)
      const handoff: Omit<Handoff, 'expiresAt'> = {
        provider: provider.id,
        state,
        nonce,
        codeVerifier: code_verifier,
        interactionId,
        browserBinding: await hashOf(binding)
      }

      await config.adapter.artifacts.upsert({
        id: handoff.state,
        kind: 'broker_handoff',
        clientId: provider.id,
        payload: handoff,
        expiresAt
      })

      // `setCookie` must reach the browser with the redirect to `url`, or the callback is refused.
      return { url: request.url, state: handoff.state, setCookie: cookieFor(handoff.state, binding, ttl) }
    },

    /** Completes the upstream leg; `cookieHeader` is the callback's `Cookie` header, as it completes only in the browser it began in. */
    async complete(currentUrl: URL, cookieHeader: string | null | undefined): Promise<BrokerCallback> {
      const state = currentUrl.searchParams.get('state')
      if (!state) throw new Error('the upstream returned no state; this sign-in did not start here')

      const stored = await config.adapter.artifacts.find('broker_handoff', state)
      if (!stored) throw new Error('this sign-in did not start here, or it expired')
      const handoff = stored.payload as Omit<Handoff, 'expiresAt'>
      // Before the handoff is spent, so a stranger holding the callback URL cannot burn it.
      const presented = cookieValue(cookieHeader, bindingCookie(state))
      const expected = handoff.browserBinding
      if (!presented || !(await constantTimeEquals(await hashOf(presented), expected))) {
        throw new Error('this sign-in did not start in this browser')
      }
      if (!(await config.adapter.artifacts.consume('broker_handoff', state))) throw new Error('this sign-in was already completed')
      await config.adapter.artifacts.destroy('broker_handoff', state)

      const provider = required(handoff.provider)

      // RFC 6749 §4.1.2.1: read only after the binding check, so it cannot forge a refusal of someone else's sign-in.
      const refused = currentUrl.searchParams.get('error')
      if (refused) {
        const description = currentUrl.searchParams.get('error_description')
        throw new OAuthError('access_denied', {
          description: `${provider.id} refused the request with ${refused}${description ? `: ${description}` : ''}`,
          spec: 'FR-F11'
        })
      }

      const resolved = await configurationFor(provider)
      const verify = verifierFor(provider, resolved)

      const result = await completeAuthorization(
        resolved,
        currentUrl,
        { redirect_uri: config.callbackUri, state: handoff.state, nonce: handoff.nonce, code_verifier: handoff.codeVerifier },
        { verifyIdToken: verify }
      )

      const failure = upstreamFailure(provider.id, result)
      if (failure || !result?.ok) throw failure
      const { token } = result

      const claims = await verify(token?.id_token)
      if (!claims.sub)
        throw new OAuthError('server_error', { description: `the ID token from ${provider.id} carried no subject`, spec: 'FR-F7' })

      // FR-F8: kept only as the upstream logout's hint, and only where logout propagates (FR-F10).
      if (provider.propagateLogout && typeof claims.sid === 'string' && token?.id_token) {
        await config.adapter.artifacts.upsert({
          id: logoutHintId(provider.id, claims.sid),
          kind: 'upstream_id_token',
          clientId: provider.id,
          payload: { idToken: token.id_token },
          expiresAt: new Date(Date.now() + (config.sessionTtl ?? DEFAULT_TTL.session) * 1000)
        })
      }

      const mapper = provider.claimMapper ?? pickClaims()
      const mapped = mapper({ ...(await userInfoOf(resolved, token, claims.sub as string)), ...claims } as Record<string, unknown>)
      const email = typeof mapped.email === 'string' ? mapped.email : undefined

      const identity: BrokeredIdentity = {
        provider: provider.id,
        subject: claims.sub as string,
        ...(email && { email }),
        claims: mapped,
        // FR-F6: provenance is the upstream's answer, never invented locally.
        ...(typeof claims.acr === 'string' && { acr: claims.acr }),
        ...(Array.isArray(claims.amr) && { amr: claims.amr as string[] }),
        ...(typeof claims.auth_time === 'number' && { authTime: new Date(claims.auth_time * 1000) }),
        ...(typeof claims.sid === 'string' && { upstreamSessionId: claims.sid }),
        // FR-F10 / NFR-S9: opt-in per provider, because keeping these makes us a credential store.
        ...(provider.retainTokens &&
          token?.access_token && {
            upstreamTokens: {
              accessToken: token.access_token,
              ...(token.refresh_token && { refreshToken: token.refresh_token }),
              ...(token.expires_in && { expiresAt: new Date(Date.now() + Number(token.expires_in) * 1000) })
            }
          })
      }

      return { interactionId: handoff.interactionId, identity, setCookie: cookieFor(handoff.state, '', 0) }
    },

    /**
     * The upstream end-session URL for a brokered session just ended, for `ProviderConfig.upstreamLogout` (FR-F8).
     * Undefined when the upstream does not propagate logout or has no `end_session_endpoint`. `then` is held
     * under the state, never sent upstream, so the round trip cannot become an open redirect.
     */
    async logoutUrl(session: Session, then: string | undefined) {
      const provider = session.idp ? providerById(session.idp) : undefined
      if (!provider?.propagateLogout || !config.postLogoutRedirectUri) return undefined
      const resolved = await configurationFor(provider)
      if (!resolved.logoutPath) return undefined

      const state = randomString()
      await config.adapter.artifacts.upsert({
        id: state,
        kind: 'broker_logout',
        clientId: provider.id,
        payload: then === undefined ? {} : { destination: then },
        expiresAt: new Date(Date.now() + (config.handoffTtl ?? DEFAULT_HANDOFF_TTL) * 1000)
      })
      const hintId = session.upstreamSessionId ? logoutHintId(provider.id, session.upstreamSessionId) : undefined
      const hint = hintId ? await config.adapter.artifacts.find('upstream_id_token', hintId) : undefined
      if (hintId) await config.adapter.artifacts.destroy('upstream_id_token', hintId)

      const url = new URL(resolved.logoutPath)
      if (hint) url.searchParams.set('id_token_hint', (hint.payload as { idToken: string }).idToken)
      url.searchParams.set('client_id', provider.clientId)
      url.searchParams.set('post_logout_redirect_uri', config.postLogoutRedirectUri)
      url.searchParams.set('state', state)
      return url.toString()
    },

    /** Where the browser goes now the upstream has signed it out too: the URL `logoutUrl` was given, once. */
    async completeLogout(currentUrl: URL) {
      const state = currentUrl.searchParams.get('state')
      const stored = state ? await config.adapter.artifacts.find('broker_logout', state) : undefined
      if (!state || !stored || !(await config.adapter.artifacts.consume('broker_logout', state))) {
        throw new Error('this logout did not start here, or it was already completed')
      }
      await config.adapter.artifacts.destroy('broker_logout', state)
      return (stored.payload as { destination?: string }).destination
    }
  }
}

export type Broker = ReturnType<typeof createBroker>
