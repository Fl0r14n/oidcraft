import type { Account, Artifact, ArtifactKind, Client, FederatedIdentity, Grant, Seconds, Session } from './types'

/**
 * Storage is a set of narrow capability stores, not one stringly-typed table (ARCHITECTURE.md §4).
 * Implement the ones a deployment needs; `fromKv` derives all of them from a single key-value store.
 */
export type Adapter = {
  clients: ClientStore
  artifacts: ArtifactStore
  sessions: SessionStore
  grants: GrantStore
  accounts: AccountStore
  keys: KeyStore
  replay: ReplayGuard
  identities?: FederatedIdentityStore
}

export type ClientStore = {
  find(clientId: string): Promise<Client | undefined>
  /** Dynamic client registration (FR-C9); omit to refuse registration at runtime. */
  create?(client: Client): Promise<void>
  update?(clientId: string, client: Partial<Client>): Promise<void>
  destroy?(clientId: string): Promise<void>
  list?(cursor?: string, limit?: number): Promise<{ clients: Client[]; cursor?: string }>
}

export type ArtifactStore = {
  /** Never clears a consumption: a poll that read the artifact before it was redeemed would revive it. */
  upsert(artifact: Artifact): Promise<void>
  find(kind: ArtifactKind, id: string): Promise<Artifact | undefined>
  /** Device flow pairs a user code with a device code (FR-C7). */
  findByUserCode?(userCode: string): Promise<Artifact | undefined>
  /**
   * Marks a live artifact used, atomically: `true` for exactly one caller, `false` when it was
   * already consumed, is unknown or has expired. A check-then-write lets two parallel redemptions
   * both win (FR-T3, FR-T4, NFR-S4).
   */
  consume(kind: ArtifactKind, id: string): Promise<boolean>
  destroy(kind: ArtifactKind, id: string): Promise<void>
  revokeByGrantId(grantId: string): Promise<void>
  /** Bounded sweep of expired rows; the runtime calls it, storage does not schedule (NFR-P3). */
  prune?(before: Date, limit: number): Promise<number>
}

export type SessionStore = {
  find(id: string): Promise<Session | undefined>
  findByAccount(accountId: string): Promise<Session[]>
  /** Upstream back-channel logout arrives keyed by the upstream session, not ours (FR-F8). */
  findByUpstreamSession?(provider: string, upstreamSessionId: string): Promise<Session[]>
  upsert(session: Session): Promise<void>
  destroy(id: string): Promise<void>
}

export type GrantStore = {
  find(id: string): Promise<Grant | undefined>
  findByAccountAndClient(accountId: string, clientId: string): Promise<Grant | undefined>
  listForAccount(accountId: string): Promise<Grant[]>
  upsert(grant: Grant): Promise<void>
  destroy(id: string): Promise<void>
}

export type AccountStore = {
  find(accountId: string): Promise<Account | undefined>
  /** Claims are resolved per request so a userinfo call never serves a stale copy (FR-C5). */
  claims(accountId: string, scopes: string[], claims: string[]): Promise<Record<string, unknown> | undefined>
}

export type KeyStore = {
  /** Newest first. The first signing-capable key of an alg signs; the rest only verify (NFR-S7). */
  active(): Promise<{ kid: string; alg: string; privateJwk: unknown; publicJwk: unknown }[]>
}

/** Replay protection for one-time values: `jti`, DPoP proofs, upstream nonces (NFR-S5). */
export type ReplayGuard = {
  /** True for exactly one caller while the value is live; false means a replay. Atomic (NFR-S5). */
  claim(namespace: string, value: string, ttl: Seconds): Promise<boolean>
}

export type FederatedIdentityStore = {
  find(provider: string, subject: string): Promise<FederatedIdentity | undefined>
  listForAccount(accountId: string): Promise<FederatedIdentity[]>
  link(identity: FederatedIdentity): Promise<void>
  unlink(accountId: string, provider: string): Promise<void>
}

/** The minimum a new backend has to implement; `fromKv` builds a full `Adapter` over it. */
export type KvStore = {
  get(key: string): Promise<string | undefined>
  /**
   * `ifAbsent` writes only when the key holds no live value, atomically — it is what single use is
   * built on, so a store that cannot do it (an eventually consistent one) cannot back a provider.
   * Resolves whether it wrote.
   */
  set(key: string, value: string, options?: { ttl?: Seconds; ifAbsent?: boolean }): Promise<boolean>
  delete(key: string): Promise<void>
  /** Prefix scan. Required because grant revocation is a range delete, not a point delete. */
  scan(prefix: string): AsyncIterable<{ key: string; value: string }>
}
