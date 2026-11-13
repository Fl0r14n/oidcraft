import type { Account, Artifact, ArtifactKind, Client, Credential, Grant, LinkedIdentity, Realm, Seconds, Session } from './types'

/** The seven stores every provider reads, plus the optional ones its features need; `fromKv` derives them all from one KV store. */
export type Adapter = {
  clients: ClientStore
  artifacts: ArtifactStore
  sessions: SessionStore
  grants: GrantStore
  accounts: AccountStore
  keys: KeyStore
  replay: ReplayGuard
  identities?: LinkedIdentityStore
  /** Only `@oidcraft/provider/accounts` reads this; a host with its own `AccountStore` never needs it (FR-I7). */
  credentials?: CredentialStore
  /** Only `createRealms` reads this, from the control plane's adapter; a single issuer never needs it (FR-M4). */
  realms?: RealmStore
}

/** What `@oidcraft/provider/broker` requires: linking and upstream logout need both (FR-F5, FR-F8). */
export type BrokeringAdapter = Adapter & {
  identities: LinkedIdentityStore
  sessions: SessionStore & Required<Pick<SessionStore, 'findByUpstreamSession'>>
}

/** What `@oidcraft/provider/accounts` requires (FR-I7). */
export type CredentialsAdapter = Adapter & { credentials: CredentialStore }

/** What a realm control plane's adapter holds (FR-M4). */
export type RealmsAdapter = Adapter & { realms: RealmStore }

/** What every first-party adapter returns, so it satisfies every entry point. */
export type FullAdapter = BrokeringAdapter & CredentialsAdapter & RealmsAdapter

/** Each store adds only the lookups the protocol needs indexed, which keeps storage from being one blob table (FR-A2). */
export type EntityStore<T, Id extends unknown[] = [id: string]> = {
  find(...id: Id): Promise<T | undefined>
  upsert(value: T): Promise<void>
  destroy(...id: Id): Promise<void>
}

/** Writes are optional so a deployment can serve a fixed set of clients; registration then refuses (FR-C9). */
export type ClientStore = Pick<EntityStore<Client>, 'find'> &
  Partial<Omit<EntityStore<Client>, 'find'>> & {
    /** In client id order; `cursor` is the previous page's, and a page without one is the last. No `limit` lists them all. */
    list?(cursor?: string, limit?: number): Promise<{ clients: Client[]; cursor?: string }>
  }

/** `upsert` never clears a consumption: a poll that read the artifact before it was redeemed would revive it. */
export type ArtifactStore = EntityStore<Artifact, [kind: ArtifactKind, id: string]> & {
  /** Device flow pairs a user code with a device code (FR-C7). */
  findByUserCode?(userCode: string): Promise<Artifact | undefined>
  /** Atomically marks a live artifact used: `true` for one caller only, `false` if consumed, unknown or expired (FR-T3, FR-T4, NFR-S4). */
  consume(kind: ArtifactKind, id: string): Promise<boolean>
  revokeByGrantId(grantId: string): Promise<void>
  revokeByFamilyId(familyId: string): Promise<void>
  /** Deleting a client takes its tokens with it, those of the client-credentials grant included, which no grant reaches (FR-T7). */
  revokeByClientId(clientId: string): Promise<void>
  /** Bounded sweep of expired rows; the runtime calls it, storage does not schedule (NFR-P3). */
  prune?(before: Date, limit: number): Promise<number>
}

export type SessionStore = EntityStore<Session> & {
  listForAccount(accountId: string): Promise<Session[]>
  /** Atomically adds a client: concurrent sign-ins must all reach the logout list (FR-C11); a session that is gone stays gone. */
  addClient(id: string, clientId: string): Promise<void>
  /** Upstream back-channel logout arrives keyed by the upstream session, not ours (FR-F8). */
  findByUpstreamSession?(provider: string, upstreamSessionId: string): Promise<Session[]>
  /** Bounded sweep of expired sessions, as `ArtifactStore.prune`; storage with its own expiry omits it (NFR-P3). */
  prune?(before: Date, limit: number): Promise<number>
}

/**
 * One grant per account and client: `upsert` for a pair another id holds writes into that grant, keeping its id and `createdAt`,
 * atomically — concurrent first consents never make a second grant or fail the insert (FR-I4).
 */
export type GrantStore = EntityStore<Grant> & {
  findByAccountAndClient(accountId: string, clientId: string): Promise<Grant | undefined>
  listForAccount(accountId: string): Promise<Grant[]>
  /** Deleting a client withdraws every consent given to it (FR-T7). */
  destroyByClientId(clientId: string): Promise<void>
}

export type AccountStore = {
  find(accountId: string): Promise<Account | undefined>
  /** Claims are resolved per request so a userinfo call never serves a stale copy (FR-C5). */
  claims(accountId: string, scopes: string[], claims: string[]): Promise<Record<string, unknown> | undefined>
}

export type ActiveKey = { kid: string; alg: string; privateJwk: unknown; publicJwk: unknown }

export type KeyStore = {
  /** Newest first. The first signing-capable key of an alg signs; the rest only verify (NFR-S7). */
  active(): Promise<ActiveKey[]>
}

/** Replay protection for one-time values: `jti`, DPoP proofs, upstream nonces (NFR-S5). */
export type ReplayGuard = {
  /** True for exactly one caller while the value is live; false means a replay. Atomic (NFR-S5). */
  claim(namespace: string, value: string, ttl: Seconds): Promise<boolean>
  /** Bounded sweep of lapsed entries: every `jti` and DPoP proof leaves one (NFR-P3). */
  prune?(before: Date, limit: number): Promise<number>
}

export type LinkedIdentityStore = EntityStore<LinkedIdentity, [provider: string, subject: string]> & {
  listForAccount(accountId: string): Promise<LinkedIdentity[]>
}

export type CredentialStore = EntityStore<Credential> & {
  findByUsername(username: string): Promise<Credential | undefined>
  /** Writes only when neither the account nor the username exists, atomically: two sign-ups racing for one name must not both win. */
  create(credential: Credential): Promise<boolean>
}

export type RealmStore = EntityStore<Realm> & {
  list(): Promise<Realm[]>
  /** Writes only when the id is free, atomically: two operators creating one realm must not both win. */
  create(realm: Realm): Promise<boolean>
}
