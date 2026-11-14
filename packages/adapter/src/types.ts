import type { ClientAuthMethod, ClientCredentials } from '@oidcraft/core'

export type { ClientAuthMethod } from '@oidcraft/core'

export type Seconds = number

export type Entity = { id: string }

export type AccountOwned = { accountId: string }

export type Timestamped = { createdAt: Date; updatedAt: Date }

/** A record that lapses. Storage enforces it in the query, so an expired one is never served (FR-T5). */
export type Expiring = { expiresAt: Date }

export type Client = ClientCredentials &
  Timestamped & {
    /** From `hashClientSecret`, for `client_secret_basic`/`_post`; `clientSecret` is only `client_secret_jwt`'s HMAC key (NFR-S11). */
    clientSecretHash?: string
    clientName?: string
    redirectUris: string[]
    postLogoutRedirectUris?: string[]
    grantTypes: string[]
    responseTypes: string[]
    scopes: string[]
    tokenEndpointAuthMethod: ClientAuthMethod
    /** FR-C21: this client alone under the FAPI 2.0 Security Profile, when the provider is not. Never set by dynamic registration. */
    profile?: 'fapi2'
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
    /** OIDC DCR 1.0 §2: `acr_values` for a request that names none, requested as a voluntary claim (FR-C23). */
    defaultAcrValues?: string[]
    /** OIDC Core §5.3.2: when set, UserInfo answers with a signed JWT rather than JSON (FR-C5). */
    userinfoSignedResponseAlg?: string
    userinfoEncryptedResponseAlg?: string
    userinfoEncryptedResponseEnc?: string
    /** RFC 8705 §2.1.2: a `tls_client_auth` client sets exactly one of these five, and its certificate must carry that value. */
    tlsClientAuthSubjectDn?: string
    tlsClientAuthSanDns?: string
    tlsClientAuthSanUri?: string
    tlsClientAuthSanIp?: string
    tlsClientAuthSanEmail?: string
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
    /** RFC 7592. A hash of the token, never the token: the provider compares, and cannot show it again (NFR-S11). */
    registrationAccessToken?: string
    /** OIDC DCR 1.0 §2. `native` may redirect to `http://localhost`; `web`, the default, may not (NFR-S2). */
    applicationType?: 'web' | 'native'
    /** May introspect other clients' access tokens not restricted to another audience (FR-C8); operator-granted, never by registration. */
    resourceServer?: boolean
  }

export type Account = AccountOwned & {
  claims: Record<string, unknown>
}

/** A user's authenticated session at the OP, independent of any one client (FR-C11, FR-T6). */
export type Session = Entity &
  AccountOwned &
  Expiring & {
    authTime: Date
    acr?: string
    amr?: string[]
    /** The upstream provider this session was authenticated by, when brokered (FR-F6). */
    idp?: string
    /** The upstream session id, so upstream logout can terminate this one (FR-F8). */
    upstreamSessionId?: string
    clients: string[]
  }

/** A durable record of what an account allowed a client — survives token revocation (FR-I4). */
export type Grant = Entity &
  AccountOwned &
  Pick<Timestamped, 'createdAt'> &
  Partial<Expiring> & {
    clientId: string
    scopes: string[]
    claims: string[]
    resources: Record<string, string[]>
  }

export type ArtifactKind =
  | 'interaction'
  | 'broker_handoff'
  | 'broker_logout'
  | 'upstream_id_token'
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
  | 'sign_in_attempts'
  | 'password_reset'
  | 'revoked_family'
  | 'passkey_challenge'

export type Artifact = Entity &
  Partial<AccountOwned> &
  Expiring & {
    kind: ArtifactKind
    grantId?: string
    /** One authorization and its descendant tokens: a replay or revoked refresh token ends this, not the grant's other devices (FR-T3). */
    familyId?: string
    clientId: string
    payload: Record<string, unknown>
    consumedAt?: Date
  }

/** A local account (FR-I7): every secret is a one-way hash or, for the TOTP secret read back, ciphertext bound to `accountId`. */
export type Credential = AccountOwned &
  Timestamped & {
    /** Normalized, and unique across the store. */
    username: string
    /** Absent on an account that signs in with passkeys alone (FR-I8). */
    passwordHash?: string
    claims: Record<string, unknown>
    totp?: { secret: string; confirmedAt?: Date }
    recoveryCodes?: string[]
    failedAttempts: number
    lockedUntil?: Date
  }

/** A local account's WebAuthn credential (FR-I8): only what verifying an assertion needs, no attestation. */
export type Passkey = AccountOwned & {
  /** base64url, as the authenticator chose it; unique across the store. */
  credentialId: string
  /** base64url SubjectPublicKeyInfo, as the browser's `getPublicKey()` reports it. */
  publicKey: string
  /** COSE: -7 ES256, -257 RS256, -8 EdDSA. */
  algorithm: number
  /** The authenticator's signature counter; 0 for one that keeps none. */
  counter: number
  transports: string[]
  /** The person's label for it. */
  name: string
  createdAt: Date
  lastUsedAt?: Date
}

/** One issuer among several in a process (FR-M4); its `id` is a DNS label, because it ends up in an issuer's host or path. */
export type Realm = Entity &
  Timestamped & {
    displayName?: string
    /** A disabled realm resolves to nothing; its data stays. */
    enabled: boolean
    /** The host's: brand, upstreams, plan. The library stores it and never reads it. */
    settings: Record<string, unknown>
  }

/** An account's link to an upstream provider — the brokering key (FR-F5). */
export type LinkedIdentity = AccountOwned & {
  provider: string
  subject: string
  email?: string
  claims: Record<string, unknown>
  linkedAt: Date
}
