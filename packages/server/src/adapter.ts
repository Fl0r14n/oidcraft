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

/**
 * What every record-holding store shares. `Id` is a tuple so a composite key reads as arguments:
 * `artifacts.find(kind, id)`, `identities.destroy(provider, subject)`. Each store adds only the
 * lookups the protocol needs indexed, which is what keeps it from being one blob table (FR-A2).
 */
export type EntityStore<T, Id extends unknown[] = [id: string]> = {
  find(...id: Id): Promise<T | undefined>
  upsert(value: T): Promise<void>
  destroy(...id: Id): Promise<void>
}

/** Writes are optional so a deployment can serve a fixed set of clients; registration then refuses (FR-C9). */
export type ClientStore = Pick<EntityStore<Client>, 'find'> &
  Partial<Omit<EntityStore<Client>, 'find'>> & {
    list?(cursor?: string, limit?: number): Promise<{ clients: Client[]; cursor?: string }>
  }

/** `upsert` never clears a consumption: a poll that read the artifact before it was redeemed would revive it. */
export type ArtifactStore = EntityStore<Artifact, [kind: ArtifactKind, id: string]> & {
  /** Device flow pairs a user code with a device code (FR-C7). */
  findByUserCode?(userCode: string): Promise<Artifact | undefined>
  /**
   * Marks a live artifact used, atomically: `true` for exactly one caller, `false` when it was
   * already consumed, is unknown or has expired. A check-then-write lets two parallel redemptions
   * both win (FR-T3, FR-T4, NFR-S4).
   */
  consume(kind: ArtifactKind, id: string): Promise<boolean>
  revokeByGrantId(grantId: string): Promise<void>
  /** Bounded sweep of expired rows; the runtime calls it, storage does not schedule (NFR-P3). */
  prune?(before: Date, limit: number): Promise<number>
}

export type SessionStore = EntityStore<Session> & {
  listForAccount(accountId: string): Promise<Session[]>
  /**
   * Records that a client signed in through this session, atomically: two clients signing in at
   * once must both be on the list logout notifies (FR-C11). A session that is gone stays gone.
   */
  addClient(id: string, clientId: string): Promise<void>
  /** Upstream back-channel logout arrives keyed by the upstream session, not ours (FR-F8). */
  findByUpstreamSession?(provider: string, upstreamSessionId: string): Promise<Session[]>
}

export type GrantStore = EntityStore<Grant> & {
  findByAccountAndClient(accountId: string, clientId: string): Promise<Grant | undefined>
  listForAccount(accountId: string): Promise<Grant[]>
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

export type FederatedIdentityStore = EntityStore<FederatedIdentity, [provider: string, subject: string]> & {
  listForAccount(accountId: string): Promise<FederatedIdentity[]>
}
