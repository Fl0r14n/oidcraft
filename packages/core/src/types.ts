export type Seconds = number

export type ClientAuthMethod =
  | 'none'
  | 'client_secret_basic'
  | 'client_secret_post'
  | 'client_secret_jwt'
  | 'private_key_jwt'
  | 'tls_client_auth'
  | 'self_signed_tls_client_auth'
  | 'attest_jwt_client_auth'

export type Client = {
  clientId: string
  clientSecret?: string
  clientName?: string
  redirectUris: string[]
  postLogoutRedirectUris?: string[]
  grantTypes: string[]
  responseTypes: string[]
  scopes: string[]
  tokenEndpointAuthMethod: ClientAuthMethod
  jwks?: { keys: unknown[] }
  jwksUri?: string
  requirePkce?: boolean
  requirePushedAuthorizationRequests?: boolean
  dpopBoundAccessTokens?: boolean
  sectorIdentifierUri?: string
  subjectType?: 'public' | 'pairwise'
  // Which upstream providers this client may broker to; empty means all enabled ones (FR-F4).
  upstreamProviders?: string[]
  backchannelLogoutUri?: string
  frontchannelLogoutUri?: string
  registrationAccessToken?: string
  createdAt: Date
  updatedAt: Date
}

export type Account = {
  accountId: string
  claims: Record<string, unknown>
}

/** A user's authenticated session at the OP, independent of any one client (FR-S1). */
export type Session = {
  id: string
  accountId: string
  authTime: Date
  acr?: string
  amr?: string[]
  /** The upstream provider this session was authenticated by, when brokered (FR-F6). */
  idp?: string
  /** The upstream session id, so upstream logout can terminate this one (FR-F8). */
  upstreamSessionId?: string
  clients: string[]
  expiresAt: Date
}

/** A durable record of what an account allowed a client — survives token revocation (FR-G1). */
export type Grant = {
  id: string
  accountId: string
  clientId: string
  scopes: string[]
  claims: string[]
  resources: Record<string, string[]>
  createdAt: Date
  expiresAt?: Date
}

export type ArtifactKind =
  | 'authorization_code'
  | 'access_token'
  | 'refresh_token'
  | 'device_code'
  | 'user_code'
  | 'pushed_authorization_request'
  | 'backchannel_authentication_request'
  | 'registration_access_token'

export type Artifact = {
  id: string
  kind: ArtifactKind
  grantId?: string
  accountId?: string
  clientId: string
  payload: Record<string, unknown>
  consumedAt?: Date
  expiresAt: Date
}

/** An account's link to an upstream provider — the brokering key (FR-F5). */
export type FederatedIdentity = {
  accountId: string
  provider: string
  subject: string
  email?: string
  claims: Record<string, unknown>
  linkedAt: Date
}
