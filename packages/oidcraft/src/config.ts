import type { Adapter } from './adapter'
import { ConfigurationError } from './errors'
import type { ClientAuthMethod, Seconds } from './types'

export type Routes = {
  discovery: string
  oauthMetadata: string
  jwks: string
  authorization: string
  token: string
  userinfo: string
  revocation: string
  introspection: string
  registration: string
  endSession: string
  deviceAuthorization: string
  pushedAuthorizationRequest: string
}

export const DEFAULT_ROUTES: Routes = {
  discovery: '/.well-known/openid-configuration',
  oauthMetadata: '/.well-known/oauth-authorization-server',
  jwks: '/jwks',
  authorization: '/authorize',
  token: '/token',
  userinfo: '/userinfo',
  revocation: '/revoke',
  introspection: '/introspect',
  registration: '/register',
  endSession: '/session/end',
  deviceAuthorization: '/device/authorize',
  pushedAuthorizationRequest: '/request'
}

export type Ttl = {
  authorizationCode: Seconds
  accessToken: Seconds
  refreshToken: Seconds
  idToken: Seconds
  session: Seconds
  interaction: Seconds
  deviceCode: Seconds
  pushedAuthorizationRequest: Seconds
}

export const DEFAULT_TTL: Ttl = {
  authorizationCode: 60,
  accessToken: 900,
  refreshToken: 1_209_600,
  idToken: 900,
  session: 1_209_600,
  interaction: 600,
  deviceCode: 600,
  pushedAuthorizationRequest: 60
}

/**
 * What the host runtime can actually supply. A feature whose capability is missing is disabled
 * rather than advertised, because advertising it in discovery would be a lie (FR-R5).
 */
export type Capabilities = {
  /** Whether a `RequestContext.clientCertificate` can ever arrive. False on Bun (`G-8`). */
  clientCertificate: boolean
}

export const DEFAULT_CAPABILITIES: Capabilities = { clientCertificate: false }

export type Features = {
  dynamicRegistration: boolean
  deviceFlow: boolean
  pushedAuthorizationRequests: boolean
  introspection: boolean
  revocation: boolean
  dpop: boolean
}

export const DEFAULT_FEATURES: Features = {
  // FR-C9: registration is off unless a deployment opts in.
  dynamicRegistration: false,
  deviceFlow: false,
  pushedAuthorizationRequests: false,
  introspection: true,
  revocation: true,
  dpop: false
}

export type ProviderConfig = {
  issuer: string
  adapter: Adapter
  /** Where the authorization endpoint sends a browser when it cannot decide alone (FR-I1). */
  interactionUrl?: string
  routes?: Partial<Routes>
  ttl?: Partial<Ttl>
  scopes?: string[]
  /** scope → the claims it releases (FR-C5). */
  claims?: Record<string, string[]>
  clientAuthMethods?: ClientAuthMethod[]
  features?: Partial<Features>
  capabilities?: Partial<Capabilities>
}

export type ResolvedConfig = {
  issuer: string
  issuerUrl: URL
  adapter: Adapter
  interactionUrl: string | undefined
  routes: Routes
  ttl: Ttl
  scopes: string[]
  claims: Record<string, string[]>
  clientAuthMethods: ClientAuthMethod[]
  features: Features
  capabilities: Capabilities
}

const MTLS_METHODS: ClientAuthMethod[] = ['tls_client_auth', 'self_signed_tls_client_auth']

const DEFAULT_SCOPES = ['openid', 'profile', 'email', 'offline_access']

const DEFAULT_CLAIMS: Record<string, string[]> = {
  profile: ['name', 'family_name', 'given_name', 'preferred_username', 'picture', 'locale', 'updated_at'],
  email: ['email', 'email_verified']
}

const DEFAULT_CLIENT_AUTH: ClientAuthMethod[] = ['client_secret_basic', 'client_secret_post', 'private_key_jwt', 'none']

export const resolveConfig = (config: ProviderConfig): ResolvedConfig => {
  const problems: string[] = []

  let issuerUrl: URL | undefined
  try {
    issuerUrl = new URL(config.issuer)
  } catch {
    problems.push(`issuer ${JSON.stringify(config.issuer)} is not an absolute URL`)
  }

  if (issuerUrl) {
    if (issuerUrl.search || issuerUrl.hash) problems.push('issuer must not carry a query string or fragment (OIDC Discovery 1.0 §3)')
    if (issuerUrl.protocol !== 'https:' && !isLoopback(issuerUrl)) {
      problems.push(`issuer ${config.issuer} must be https outside loopback — tokens are bearer credentials (NFR-S1)`)
    }
  }

  if (!config.adapter) problems.push('adapter is required: the core performs no I/O of its own (FR-A1)')

  const routes = { ...DEFAULT_ROUTES, ...config.routes }
  for (const [name, path] of Object.entries(routes)) {
    if (!path.startsWith('/')) problems.push(`route ${name} must be an absolute path, got ${JSON.stringify(path)}`)
  }
  const collisions = duplicates(Object.values(routes))
  if (collisions.length) problems.push(`routes must be distinct; ${collisions.join(', ')} is used more than once`)

  const ttl = { ...DEFAULT_TTL, ...config.ttl }
  for (const [name, seconds] of Object.entries(ttl)) {
    if (!Number.isInteger(seconds) || seconds <= 0) problems.push(`ttl.${name} must be a positive whole number of seconds, got ${seconds}`)
  }

  const scopes = config.scopes ?? DEFAULT_SCOPES
  if (!scopes.includes('openid'))
    problems.push('scopes must include "openid" — without it this is not an OpenID Provider (OIDC Core §3.1.2.1)')

  const features = { ...DEFAULT_FEATURES, ...config.features }
  const capabilities = { ...DEFAULT_CAPABILITIES, ...config.capabilities }
  const clientAuthMethods = config.clientAuthMethods ?? DEFAULT_CLIENT_AUTH

  if (!clientAuthMethods.length) problems.push('clientAuthMethods must not be empty')

  const mtls = clientAuthMethods.filter(method => MTLS_METHODS.includes(method))
  if (mtls.length && !capabilities.clientCertificate) {
    problems.push(
      `${mtls.join(' and ')} cannot work here: this runtime supplies no RequestContext.clientCertificate. ` +
        'Remove the method, or set capabilities.clientCertificate once the host can provide one (FR-R5, G-8)'
    )
  }

  if (features.dynamicRegistration && !config.adapter?.clients.create) {
    problems.push('features.dynamicRegistration needs an adapter whose clients store implements create (FR-C9)')
  }

  if (features.deviceFlow && !config.adapter?.artifacts.findByUserCode) {
    problems.push('features.deviceFlow needs an adapter whose artifacts store implements findByUserCode (FR-C7)')
  }

  if (problems.length) throw new ConfigurationError(problems)

  return {
    issuer: stripTrailingSlash(config.issuer),
    issuerUrl: issuerUrl as URL,
    adapter: config.adapter,
    interactionUrl: config.interactionUrl,
    routes,
    ttl,
    scopes,
    claims: config.claims ?? DEFAULT_CLAIMS,
    clientAuthMethods,
    features,
    capabilities
  }
}

const isLoopback = (url: URL) => url.hostname === 'localhost' || url.hostname === '127.0.0.1' || url.hostname === '[::1]'

const stripTrailingSlash = (value: string) => (value.endsWith('/') ? value.slice(0, -1) : value)

const duplicates = (values: string[]) => [...new Set(values.filter((value, i) => values.indexOf(value) !== i))]
