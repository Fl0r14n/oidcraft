import type { Adapter } from 'oidcraft'
import * as client from 'openid-client'
import { pickClaims } from './claims'
import { type SelectionHints, selectUpstream } from './select'
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

export const createBroker = (config: BrokerConfig) => {
  // Latency only: discovery documents are immutable enough to cache, and a cold process simply
  // fetches them again. No request's outcome depends on whether this is warm (FR-A1).
  const discovered = new Map<string, Promise<client.Configuration>>()

  const execute = config.allowInsecure ? [client.allowInsecureRequests] : []

  const configurationFor = (provider: UpstreamProvider) => {
    let found = discovered.get(provider.id)
    if (!found) {
      found = client.discovery(new URL(provider.issuer), provider.clientId, provider.clientSecret, undefined, {
        ...(execute.length && { execute })
      })
      discovered.set(provider.id, found)
    }
    return found
  }

  const providerById = (id: string) => config.providers.find(provider => provider.id === id)

  return {
    providers: config.providers,

    /** Home-realm discovery (FR-F4); returns the candidates when it cannot decide alone. */
    select: (hints: SelectionHints, explicit?: string) => selectUpstream(config.providers, hints, explicit),

    /**
     * Begins the upstream leg and records the handoff against the downstream interaction it will
     * resume (FR-F3). The handoff is single-use, expiring, and carries the PKCE verifier — it never
     * travels in the URL.
     */
    async start(interactionId: string, providerId: string, options: { loginHint?: string; prompt?: string; uiLocales?: string } = {}) {
      const provider = providerById(providerId)
      if (!provider) throw new Error(`unknown upstream provider ${providerId}`)

      const configuration = await configurationFor(provider)
      const codeVerifier = client.randomPKCECodeVerifier()
      const handoff: Handoff = {
        provider: provider.id,
        state: client.randomState(),
        nonce: client.randomNonce(),
        codeVerifier,
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

      const url = client.buildAuthorizationUrl(configuration, {
        redirect_uri: config.callbackUri,
        scope: provider.scopes.join(' '),
        state: handoff.state,
        nonce: handoff.nonce,
        code_challenge: await client.calculatePKCECodeChallenge(codeVerifier),
        code_challenge_method: 'S256',
        ...provider.authorizationParams,
        ...(options.loginHint && { login_hint: options.loginHint }),
        // FR-F9: a downstream prompt=login must force a fresh upstream authentication, not be
        // satisfied by whatever session the upstream happens to still hold.
        ...(options.prompt && { prompt: options.prompt }),
        ...(options.uiLocales && { ui_locales: options.uiLocales })
      })

      return { url: url.href, state: handoff.state }
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
      const provider = providerById(handoff.provider)
      if (!provider) throw new Error(`unknown upstream provider ${handoff.provider}`)

      const configuration = await configurationFor(provider)
      const tokens = await client.authorizationCodeGrant(configuration, currentUrl, {
        expectedState: handoff.state,
        expectedNonce: handoff.nonce,
        pkceCodeVerifier: handoff.codeVerifier
      })

      const claims = tokens.claims()
      if (!claims?.sub) throw new Error('the upstream ID token carried no subject')

      const mapper = provider.claimMapper ?? pickClaims()
      const mapped = mapper(claims as Record<string, unknown>)
      const email = typeof mapped.email === 'string' ? mapped.email : undefined

      const identity: BrokeredIdentity = {
        provider: provider.id,
        subject: claims.sub,
        ...(email && { email }),
        claims: mapped,
        // FR-F6: provenance is the upstream's answer, never invented locally.
        ...(typeof claims.acr === 'string' && { acr: claims.acr }),
        ...(Array.isArray(claims.amr) && { amr: claims.amr as string[] }),
        ...(typeof claims.auth_time === 'number' && { authTime: new Date(claims.auth_time * 1000) }),
        ...(typeof claims.sid === 'string' && { upstreamSessionId: claims.sid }),
        // FR-F10 / NFR-S9: opt-in per provider, because keeping these makes us a credential store.
        ...(provider.retainTokens &&
          tokens.access_token && {
            upstreamTokens: {
              accessToken: tokens.access_token,
              ...(tokens.refresh_token && { refreshToken: tokens.refresh_token }),
              ...(tokens.expires_in && { expiresAt: new Date(Date.now() + tokens.expires_in * 1000) })
            }
          })
      }

      return { interactionId: handoff.interactionId, identity }
    }
  }
}

export type Broker = ReturnType<typeof createBroker>
