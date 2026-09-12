import type { FederatedIdentity } from 'oidcraft'

/** An upstream OP this provider brokers to. Discovery is by issuer; nothing is hardcoded (FR-F1). */
export type UpstreamProvider = {
  id: string
  issuer: string
  clientId: string
  clientSecret?: string
  scopes: string[]
  /** Extra authorization-request parameters, e.g. `prompt`, `hd`, `domain_hint`. */
  authorizationParams?: Record<string, string>
  /** Email domains this provider owns, for home-realm discovery (FR-F4). */
  domains?: string[]
  /** Human-readable, for an upstream-selection screen. */
  label?: string
  /** Maps upstream claims onto local ones. Without it only `sub` is trusted (FR-F7). */
  claimMapper?: ClaimMapper
  /** Keep the upstream tokens for downstream API calls. Off by default — it is a credential store (NFR-S9). */
  retainTokens?: boolean
  linkPolicy?: LinkPolicy
}

export type ClaimMapper = (upstream: Record<string, unknown>) => Record<string, unknown>

/**
 * How a brokered identity attaches to a local account.
 * `subject` alone is the only safe default: matching on email lets an upstream that does not verify
 * addresses take over any local account with that address (NFR-S8).
 */
export type LinkPolicy = 'subject' | 'verified-email' | 'interactive'

export type Handoff = {
  provider: string
  state: string
  nonce: string
  codeVerifier: string
  /** The downstream interaction this handoff resumes once the upstream returns (FR-F3). */
  interactionId: string
  expiresAt: Date
}

/** How the upstream round trip ended, for the host to act on. */
export type FederationCallback = {
  interactionId: string
  identity: BrokeredIdentity
}

export type BrokeredIdentity = Omit<FederatedIdentity, 'accountId' | 'linkedAt'> & {
  /** Present only when the upstream issued one and `retainTokens` is set. */
  upstreamTokens?: { accessToken: string; refreshToken?: string; expiresAt?: Date }
  upstreamSessionId?: string
  acr?: string
  amr?: string[]
  authTime?: Date
}
