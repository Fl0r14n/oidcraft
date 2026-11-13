export type OAuthFetch = (input: string | URL | Request, init?: RequestInit) => Promise<Response>

/** Every client authentication method in the RFC 7591 `token_endpoint_auth_method` registry. */
export type ClientAuthMethod =
  | 'none'
  | 'client_secret_basic'
  | 'client_secret_post'
  | 'client_secret_jwt'
  | 'private_key_jwt'
  | 'tls_client_auth'
  | 'self_signed_tls_client_auth'
  | 'attest_jwt_client_auth'

/** The methods this library sends as a client (RFC 6749 §2.3.1); a public client uses `none`. */
export type TokenAuthMethod = Extract<ClientAuthMethod, 'client_secret_post' | 'client_secret_basic' | 'none'>

/** A client's identity, whichever side holds it. */
export type ClientCredentials = {
  clientId: string
  clientSecret?: string
}

export type ClientCredentialConfig = ClientCredentials & {
  tokenPath: string
  revokePath?: string
  scope?: string
  userPath?: string
  introspectionPath?: string
  tokenEndpointAuthMethod?: TokenAuthMethod
  /** Development only: permits `http` endpoints, which are otherwise refused. */
  allowInsecure?: boolean
}

export type ResourceOwnerConfig = ClientCredentialConfig

export type ImplicitConfig = Pick<ClientCredentials, 'clientId'> & {
  authorizePath: string
  revokePath?: string
  scope?: string
  logoutPath?: string
  /** used when the call passes none */
  redirectUri?: string
  /** used when the call passes none */
  logoutRedirectUri?: string
  userPath?: string
  allowInsecure?: boolean
}

export type AuthorizationCodeConfig = ResourceOwnerConfig & {
  authorizePath: string
  logoutPath?: string
  /** used when the call passes none */
  redirectUri?: string
  /** used when the call passes none */
  logoutRedirectUri?: string
}

export type AuthorizationCodePKCEConfig = AuthorizationCodeConfig & {
  pkce?: boolean
}

export type OpenIdConfig = AuthorizationCodePKCEConfig & {
  /** where the well-known document lives */
  issuerPath: string
  /** the issuer as asserted in `iss`, set by discovery; falls back to `issuerPath`, and may be Entra's `{tenantid}` template */
  issuer?: string
  jwksUri?: string
  /** RFC 9207: the provider returns `iss` on the authorization response, so a missing one is an error. Set by discovery. */
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
  /** generated when omitted */
  state?: string
  /** extra authorization request parameters, merged last — `ui_locales`, `login_hint`, Auth0's `audience` */
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

/** Not an `enum`, which `erasableSyntaxOnly` forbids: a member in type position is `typeof OAuthType.IMPLICIT`. */
export const OAuthType = {
  RESOURCE: 'password',
  AUTHORIZATION_CODE: 'code',
  IMPLICIT: 'token',
  CLIENT_CREDENTIAL: 'client_credentials'
} as const

export type OAuthType = (typeof OAuthType)[keyof typeof OAuthType]

/** Open, as RFC 6749 §5.1 permits additional parameters; name the ones you use through `TExtra`. */
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

/** What an authorization request carries across the round trip; store it scoped to that one request, never process-wide. */
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

/** The well-known document as a client reads it: all optional and open. Pinned to the provider's `metadata` by a contract test. */
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

/** Resolves an issuer's well-known document; share one from `createDiscovery` across instances to fetch each issuer once. */
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
  /** builds the authorization URL and handoff without redirecting; override it for an endpoint `extras` cannot express */
  authorizationUrl: (parameters: AuthorizationCodeParameters, config?: Partial<OpenIdConfig>) => Promise<AuthorizationRequest>
  resourceOwnerLogin: (parameters: ResourceOwnerParameters, config?: ResourceOwnerConfig) => Promise<OAuthToken | undefined>
  clientCredentialLogin: (config?: ClientCredentialConfig) => Promise<OAuthToken | undefined>
  openIdConfiguration: (config?: Partial<OpenIdConfig>) => Promise<OpenIdConfiguration | undefined>
  userInfo: (config?: Partial<OpenIdConfig>, request?: OAuthFetch) => Promise<UserInfo | undefined>
  introspect: (token?: OAuthToken, config?: Partial<OpenIdConfig>) => Promise<IntrospectInfo | undefined>
}
