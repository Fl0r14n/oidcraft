import {
  applyDiscovery,
  beginAuthorization,
  completeAuthorization,
  createDiscovery,
  createIdTokenVerifier,
  type IdTokenVerifier,
  type OAuthToken,
  type OpenIdConfig
} from '@oidcraft/core'
import type { Adapter } from 'oidcraft'
import { OAuthError, type SelectionHints, selectUpstream } from 'oidcraft'
import { pickClaims } from './claims'
import type { BrokeredIdentity, FederationCallback, Handoff, UpstreamProvider } from './types'

export type BrokerConfig = {
  adapter: Adapter
  providers: UpstreamProvider[]
  /** Where the upstream sends the browser back. Must be registered with every upstream. */
  callbackUri: string
  /** Seconds a handoff stays usable. Short on purpose: it is a single-use one-way ticket (FR-F3). */
  handoffTtl?: number
  /** Development only: lets discovery and the token exchange run over http. */
  allowInsecure?: boolean
}

const DEFAULT_HANDOFF_TTL = 600

/** The errors the RP core reports by name. Everything else on `error` came from the upstream itself. */
const CORE_ERRORS: Record<string, { code: 'server_error' | 'access_denied'; description: string; spec: string }> = {
  'Invalid state': {
    code: 'access_denied',
    description: 'the upstream callback did not match the handoff that started it',
    spec: 'RFC 6749 §10.12'
  },
  'Invalid issuer': {
    code: 'access_denied',
    description: 'the upstream callback was issued by a different authorization server than the one asked',
    spec: 'RFC 9207 §2.4'
  },
  'Missing issuer': {
    code: 'access_denied',
    description: 'the upstream advertises the iss parameter but did not send it',
    spec: 'RFC 9207 §2.4'
  },
  'Invalid nonce': { code: 'access_denied', description: 'the upstream ID token did not carry the nonce it was asked for', spec: 'FR-F3' },
  'Invalid token': { code: 'access_denied', description: 'the upstream ID token failed verification', spec: 'OIDC Core §3.1.3.7' }
}

/**
 * FR-F11: a failed upstream leg leaves the downstream client with a well-formed OAuth error rather
 * than a stack trace or a silent `undefined`. The RP core reports a failure by returning a token
 * carrying `error` and no credential, so the cause has to be read back out of that here.
 */
const upstreamFailure = (provider: string, token: OAuthToken | undefined) => {
  if (!token) {
    return new OAuthError('server_error', {
      description: `the callback from ${provider} carried neither a code nor an error`,
      spec: 'FR-F11'
    })
  }
  const error = typeof token.error === 'string' ? token.error : undefined
  if (!error) return undefined
  // A token endpoint that does not answer leaves the core checking a nonce against a response that
  // never arrived, which it cannot tell apart from a wrong one. This can: a real nonce mismatch comes
  // with an ID token to have mismatched.
  if (error === 'Invalid nonce' && !token.id_token && !token.access_token) {
    return new OAuthError('temporarily_unavailable', { description: `${provider} did not answer the token request`, spec: 'FR-F11' })
  }
  const known = CORE_ERRORS[error]
  if (known) return new OAuthError(known.code, { description: `${provider}: ${known.description}`, spec: known.spec })
  const described = typeof token.error_description === 'string' ? `: ${token.error_description}` : ''
  return new OAuthError('access_denied', { description: `${provider} refused the request with ${error}${described}`, spec: 'FR-F11' })
}

export const createBroker = (config: BrokerConfig) => {
  // FR-F6/FR-F7 read `sub`, `acr`, `amr` and `auth_time` off the upstream ID token, so a provider
  // configured without `openid` could never produce a brokered identity. Failing here rather than at
  // the callback (NFR-D2).
  for (const provider of config.providers) {
    if (!provider.scopes.includes('openid')) {
      throw new OAuthError('server_error', {
        description: `upstream ${provider.id} is configured without the openid scope, so it will never return an ID token to broker`,
        spec: 'FR-F1'
      })
    }
  }

  // Latency only: discovery documents are immutable enough to cache, and a cold process simply
  // fetches them again. No request's outcome depends on whether this is warm (FR-A1).
  const discover = createDiscovery()
  const verifiers = new Map<string, IdTokenVerifier>()

  const configurationFor = async (provider: UpstreamProvider) => {
    const base: Partial<OpenIdConfig> = {
      issuerPath: provider.issuer,
      clientId: provider.clientId,
      ...(provider.clientSecret !== undefined && { clientSecret: provider.clientSecret }),
      ...(provider.tokenAuthMethod && { tokenAuthMethod: provider.tokenAuthMethod }),
      scope: provider.scopes.join(' '),
      // FR-C3 applies to what this provider asks of others as much as to what it demands of its own
      // clients; there is no upstream worth brokering to that cannot do S256.
      pkce: true,
      ...(config.allowInsecure && { allowInsecure: true })
    }
    // `applyDiscovery` refuses a document asserting an issuer other than the one it was fetched from
    // (OIDC Discovery 1.0 §4.3), which is the check that makes the endpoints below trustworthy.
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
      // Held per provider because jose caches the remote key set on the verifier; one built per
      // callback refetches the JWKS every sign-in.
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

    /**
     * Begins the upstream leg and records the handoff against the downstream interaction it will
     * resume (FR-F3). The handoff is single-use, expiring, and carries the PKCE verifier — it never
     * travels in the URL.
     */
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
          // FR-F9: the downstream client asked for these, and satisfying them from whatever session
          // the upstream happens to hold would answer a question nobody asked.
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

      const handoff: Handoff = {
        provider: provider.id,
        state,
        nonce,
        codeVerifier: code_verifier,
        interactionId,
        expiresAt: new Date(Date.now() + (config.handoffTtl ?? DEFAULT_HANDOFF_TTL) * 1000)
      }

      await config.adapter.artifacts.upsert({
        id: handoff.state,
        kind: 'federation_handoff',
        clientId: provider.id,
        payload: handoff as unknown as Record<string, unknown>,
        expiresAt: handoff.expiresAt
      })

      return { url: request.url, state: handoff.state }
    },

    /** Completes the upstream leg and yields the identity plus the interaction to resume. */
    async complete(currentUrl: URL): Promise<FederationCallback> {
      const state = currentUrl.searchParams.get('state')
      if (!state) throw new Error('the upstream returned no state; this sign-in did not start here')

      const stored = await config.adapter.artifacts.find('federation_handoff', state)
      if (!stored) throw new Error('this sign-in did not start here, or it expired')
      // Single-use: a replayed callback must not mint a second identity.
      await config.adapter.artifacts.destroy('federation_handoff', state)

      const handoff = stored.payload as unknown as Handoff
      const provider = required(handoff.provider)

      // RFC 6749 §4.1.2.1: an error on the redirect uri is the upstream's answer, and there is no
      // code to exchange. It is read here, after the handoff bound the callback, so it cannot be
      // forged into a refusal for a sign-in somebody else started.
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

      const token = await completeAuthorization(
        resolved,
        currentUrl,
        { redirect_uri: config.callbackUri, state: handoff.state, nonce: handoff.nonce, code_verifier: handoff.codeVerifier },
        { verifyIdToken: verify }
      )

      const failure = upstreamFailure(provider.id, token)
      if (failure) throw failure

      // Verified already, as part of the nonce check; this re-reads the claims, which costs one
      // signature check and no network because jose caches the key set on the verifier.
      const claims = await verify(token?.id_token)
      if (!claims.sub)
        throw new OAuthError('server_error', { description: `the ID token from ${provider.id} carried no subject`, spec: 'FR-F7' })

      const mapper = provider.claimMapper ?? pickClaims()
      const mapped = mapper(claims as Record<string, unknown>)
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

      return { interactionId: handoff.interactionId, identity }
    }
  }
}

export type Broker = ReturnType<typeof createBroker>
