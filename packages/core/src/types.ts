export type OAuthFetch = (input: string | URL | Request, init?: RequestInit) => Promise<Response>

/** How client credentials reach a token, revocation or introspection endpoint. `client_secret_post`
 * carries them in the body and is what most providers accept; some only honour the Basic header, and
 * a public client sends neither (RFC 6749 §2.3.1). */
export type TokenAuthMethod = 'client_secret_post' | 'client_secret_basic' | 'none'

export type ClientCredentialConfig = {
  tokenPath: string
  revokePath?: string
  clientId: string
  clientSecret?: string
  scope?: string
  userPath?: string
  introspectionPath?: string
  tokenAuthMethod?: TokenAuthMethod
  /** Development only. Every endpoint this library fetches or sends a browser to must be https
   * otherwise: a code or token crossing http is a code or token anyone on the path already has. */
  allowInsecure?: boolean
}

export type ResourceOwnerConfig = ClientCredentialConfig

export type ImplicitConfig = {
  authorizePath: string
  revokePath?: string
  clientId: string
  scope?: string
  logoutPath?: string
  redirectUri?: string // if not using OAuthParameters
  logoutRedirectUri?: string // if not using OAuthParameters
  userPath?: string
  allowInsecure?: boolean
}

export type AuthorizationCodeConfig = ResourceOwnerConfig & {
  authorizePath: string
  logoutPath?: string
  redirectUri?: string // if not using OAuthParameters
  logoutRedirectUri?: string // if not using OAuthParameters
}

export type AuthorizationCodePKCEConfig = AuthorizationCodeConfig & {
  pkce?: boolean
}

export type OpenIdConfig = AuthorizationCodePKCEConfig & {
  /** where the well-known document lives */
  issuerPath: string
  /** the issuer identifier as the provider asserts it in `iss`, filled in by discovery. Usually the same
   * as `issuerPath`; Entra's multi-tenant document advertises a `{tenantid}` template instead, which the
   * id-token verifier resolves per token. Falls back to `issuerPath` when absent. */
  issuer?: string
  jwksUri?: string
  /** RFC 9207: the provider states it returns `iss` on the authorization response. That turns a missing
   * `iss` from an omission into an error, which is the whole point of the parameter. Set by discovery. */
  issuerParameter?: boolean
}

export type ResourceOwnerParameters = {
  username: string
  password: string
}

export type AuthorizationCodeParameters = {
  accessType?: 'online' | 'offline'
  prompt?: 'none' | 'consent' | 'login' | 'select_account'
  redirectUri: string
  responseType: typeof OAuthType.IMPLICIT | typeof OAuthType.AUTHORIZATION_CODE | string
  /** omit to get a generated one — `completeAuthorization` only checks state it issued or was given here */
  state?: string
  /** merged last, so anything the standard set does not cover — `ui_locales`, `login_hint`, `acr_values`,
   * Auth0's `audience`, Entra's `resource` — reaches the authorization endpoint without an override */
  extras?: Record<string, string | undefined>
}

export type OAuthParameters = ResourceOwnerParameters | AuthorizationCodeParameters
export type OAuthTypeConfig =
  | OpenIdConfig
  | AuthorizationCodePKCEConfig
  | AuthorizationCodeConfig
  | ImplicitConfig
  | ResourceOwnerConfig
  | ClientCredentialConfig

/** A const object rather than an `enum`: an enum is not erasable syntax, and this package is compiled
 * under `erasableSyntaxOnly` (ARCHITECTURE.md §9.2). `OAuthType` remains usable as both a value and a
 * type; only a *member* in type position has to be written `typeof OAuthType.IMPLICIT`. */
export const OAuthType = {
  RESOURCE: 'password',
  AUTHORIZATION_CODE: 'code',
  IMPLICIT: 'token',
  CLIENT_CREDENTIAL: 'client_credentials'
} as const

export type OAuthType = (typeof OAuthType)[keyof typeof OAuthType]

/** Open on purpose: RFC 6749 §5.1 permits additional parameters, and this arrives parsed off the wire, so
 * there is no author to protect from a typo. Name the extras you use through `TExtra` for autocomplete. */
export type OAuthToken<TExtra = unknown> = {
  id_token?: string
  access_token?: string
  refresh_token?: string
  token_type?: string
  state?: string
  error?: string
  error_description?: string
  expires_in?: number | string
  refresh_expires_in?: number | string
  scope?: string
  code_verifier?: string
  nonce?: string
  type?: OAuthType
  expires?: number
  code?: string

  [x: string]: any
} & TExtra

/** What an authorization request must carry across the user's round trip to the provider, and nothing else.
 * The caller owns where it lives: browser storage in an SPA, a cookie or a server-side store in a confidential
 * client. Whatever holds it must be scoped to the one request — a process-wide holder is another user's nonce. */
export type AuthorizationHandoff = {
  redirect_uri: string
  state?: string
  nonce?: string
  code_verifier?: string
}

export type AuthorizationRequest = {
  url: string
  handoff: AuthorizationHandoff
}

export const OAuthStatus = {
  NOT_AUTHORIZED: 'NOT_AUTHORIZED',
  AUTHORIZED: 'AUTHORIZED',
  DENIED: 'DENIED'
} as const

export type OAuthStatus = (typeof OAuthStatus)[keyof typeof OAuthStatus]

/** The well-known document as a client reads it: everything optional, because every member of it is
 * optional to some provider, and open, because a provider may publish anything else alongside. An OP
 * writing one wants the opposite shape — see `packages/oidcraft`'s `metadata`, which is pinned to this
 * type by `metadata.contract.test.ts` so the two cannot drift apart silently. */
export type OpenIdConfiguration = {
  issuer?: string
  authorization_endpoint?: string
  introspection_endpoint?: string
  token_endpoint?: string
  userinfo_endpoint?: string
  end_session_endpoint?: string
  revocation_endpoint?: string
  jwks_uri?: string
  scopes_supported?: string[]
  code_challenge_methods_supported?: string[]
  authorization_response_iss_parameter_supported?: boolean

  [x: string]: any
}

/** Resolves an issuer's well-known document. `createDiscovery` builds a caching one; a consumer may pass
 * its own — one shared across per-request instances is how a server fetches each issuer once. */
export type Discovery = (config?: Partial<OpenIdConfig>) => Promise<OpenIdConfiguration | undefined>

/** The standard OIDC claims, open for the rest — a claim set is whatever the provider issues. */
export type UserInfo<TClaims = unknown> = {
  email?: string
  email_verified?: boolean
  family_name?: string
  given_name?: string
  name?: string
  preferred_username?: string
  sub?: string
  address?: object
  picture?: string
  locale?: string

  [x: string]: any
} & TClaims

export type IntrospectInfo = UserInfo & {
  active: boolean
  scope: string
  client_id?: string
  username: string
  exp: number
}

export interface OAuthFunctions {
  refresh: (token?: OAuthToken, config?: Partial<OpenIdConfig>) => Promise<OAuthToken | undefined>
  revoke: (token?: OAuthToken, config?: Partial<OpenIdConfig>) => Promise<void>
  authorize: (token?: OAuthToken, config?: Partial<OpenIdConfig>) => Promise<OAuthToken | undefined>
  /** builds the authorization URL and the state that must survive until the redirect comes back. It performs
   * no redirect and writes nothing — override it for a provider whose authorization endpoint is non-standard
   * beyond what `AuthorizationCodeParameters.extras` can express. */
  authorizationUrl: (parameters: AuthorizationCodeParameters, config?: Partial<OpenIdConfig>) => Promise<AuthorizationRequest>
  resourceOwnerLogin: (parameters: ResourceOwnerParameters, config?: ResourceOwnerConfig) => Promise<OAuthToken | undefined>
  clientCredentialLogin: (config?: ClientCredentialConfig) => Promise<OAuthToken | undefined>
  openIdConfiguration: (config?: Partial<OpenIdConfig>) => Promise<OpenIdConfiguration | undefined>
  userInfo: (config?: Partial<OpenIdConfig>, request?: OAuthFetch) => Promise<UserInfo | undefined>
  introspect: (token?: OAuthToken, config?: Partial<OpenIdConfig>) => Promise<IntrospectInfo | undefined>
}
