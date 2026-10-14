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
  /** RFC 8705 §3: bind access tokens to the client's certificate. */
  certificateBoundAccessTokens?: boolean
  sectorIdentifierUri?: string
  /** RFC 9068. Opaque by default, because a revoked opaque token stops working at once (FR-T2). */
  accessTokenFormat?: 'opaque' | 'jwt'
  /** OIDC DCR 1.0 §2. Unset, the provider's first key signs (FR-T1). */
  idTokenSignedResponseAlg?: string
  /** OIDC Core §5.3.2: when set, UserInfo answers with a signed JWT rather than JSON (FR-C5). */
  userinfoSignedResponseAlg?: string
  userinfoEncryptedResponseAlg?: string
  userinfoEncryptedResponseEnc?: string
  /** RFC 8705 §2.1.1: the subject DN the client's certificate must carry. */
  tlsClientAuthSubjectDn?: string
  /** OIDC Front-Channel Logout 1.0 §2: whether the iframe URL must carry `iss` and `sid`. */
  frontchannelLogoutSessionRequired?: boolean
  subjectType?: 'public' | 'pairwise'
  // Which upstream providers this client may broker to; empty means all enabled ones (FR-F4).
  upstreamProviders?: string[]
  backchannelLogoutUri?: string
  /** OIDC CIBA 1.0 §7.1. `push` is out of scope (FR-C17). */
  backchannelTokenDeliveryMode?: 'poll' | 'ping'
  /** OIDC CIBA 1.0 §4: where a ping-mode client is told its result is ready. Required for ping. */
  backchannelClientNotificationEndpoint?: string
  frontchannelLogoutUri?: string
  registrationAccessToken?: string
  /**
   * May introspect access tokens issued to other clients, unless a token is restricted to another
   * audience (FR-C8). Never set by dynamic registration: it is the operator's to grant.
   */
  resourceServer?: boolean
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

/** A durable record of what an account allowed a client — survives token revocation (FR-I4). */
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
  | 'interaction'
  | 'federation_handoff'
  | 'authorization_code'
  | 'access_token'
  | 'refresh_token'
  | 'device_code'
  | 'user_code'
  | 'pushed_authorization_request'
  | 'backchannel_authentication_request'
  | 'registration_access_token'
  | 'authorization_details_consent'
  | 'dpop_nonce'
  | 'authorization_response'
  | 'user_code_attempts'
  | 'password_reset'

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
/**
 * What `oidcraft/accounts` keeps per local account (FR-I7). Every secret here is either a one-way hash
 * or, for the TOTP secret the server must read back, ciphertext bound to `accountId`.
 */
export type Credential = {
  accountId: string
  /** Normalized, and unique across the store. */
  username: string
  passwordHash: string
  claims: Record<string, unknown>
  totp?: { secret: string; confirmedAt?: Date }
  recoveryCodes?: string[]
  failedAttempts: number
  lockedUntil?: Date
  createdAt: Date
  updatedAt: Date
}

export type FederatedIdentity = {
  accountId: string
  provider: string
  subject: string
  email?: string
  claims: Record<string, unknown>
  linkedAt: Date
}
