import type {
  Account,
  Artifact,
  ArtifactKind,
  Client,
  Credential,
  EpochMillis,
  Grant,
  LinkedIdentity,
  Passkey,
  Realm,
  Seconds,
  Session
} from './types'

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
  /** Only `@oidcraft/provider/accounts` reads this, for passkeys (FR-I8). */
  passkeys?: PasskeyStore
  /** Only `createRealms` reads this, from the control plane's adapter; a single issuer never needs it (FR-M4). */
  realms?: RealmStore
}

/** What `@oidcraft/provider/broker` requires: linking and upstream logout need both (FR-F5, FR-F8). */
export type BrokeringAdapter = Adapter & {
  identities: LinkedIdentityStore
  sessions: SessionStore & Required<Pick<SessionStore, 'listByUpstreamSession'>>
}

/** What `@oidcraft/provider/accounts` requires (FR-I7, FR-I8). */
export type CredentialsAdapter = Adapter & { credentials: CredentialStore; passkeys: PasskeyStore }

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

/**
 * A record whose fields change one at a time: `update` writes only the fields given, to a record that exists, and resolves
 * whether there was one; it never creates one. `Key` names what identifies a record, which never changes: two writers changing
 * different fields of one record both land, as two `upsert`s of what each read would not.
 */
export type UpdatableStore<T, Key extends keyof T> = EntityStore<T> & {
  /** A field given as `undefined` is cleared. */
  update(id: string, fields: { [Field in Exclude<keyof T, Key>]?: T[Field] | undefined }): Promise<boolean>
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
  destroyByGrantId(grantId: string): Promise<void>
  destroyByFamilyId(familyId: string): Promise<void>
  /** Deleting a client takes its tokens with it, those of the client-credentials grant included, which no grant reaches (FR-T7). */
  destroyByClientId(clientId: string): Promise<void>
  /** Bounded sweep of expired rows; the runtime calls it, storage does not schedule (NFR-P3). */
  prune?(before: EpochMillis, limit: number): Promise<number>
}

/** `update` writes a live session only, and never its clients, which `addClient` alone adds to (FR-I10, FR-C11). */
export type SessionStore = UpdatableStore<Session, 'id' | 'clients'> & {
  listForAccount(accountId: string): Promise<Session[]>
  /** Atomically adds a client: concurrent sign-ins must all reach the logout list (FR-C11); a session that is gone stays gone. */
  addClient(id: string, clientId: string): Promise<void>
  /** Upstream back-channel logout arrives keyed by the upstream session, not ours (FR-F8). */
  listByUpstreamSession?(upstream: string, upstreamSessionId: string): Promise<Session[]>
  /** Bounded sweep of expired sessions, as `ArtifactStore.prune`; storage with its own expiry omits it (NFR-P3). */
  prune?(before: EpochMillis, limit: number): Promise<number>
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
  /**
   * A consent: adds the grant's scopes, claims and resources to the live grant of its account and client,
   * or stores it when there is none, atomically however many land at once; an expired one is replaced,
   * under the new id. Returns what is stored (FR-I4).
   */
  merge(grant: Grant): Promise<Grant>
}

export type AccountStore = {
  find(accountId: string): Promise<Account | undefined>
  /**
   * Claims are resolved per request so a userinfo call never serves a stale copy (FR-C5): what `scopes` release, and
   * besides them each claim in `claims`, which the person consented to by name through the `claims` parameter (FR-C22).
   */
  claims(accountId: string, scopes: string[], claims: string[]): Promise<Record<string, unknown> | undefined>
}

export type ActiveKey = { kid: string; alg: string; privateJwk: unknown; publicJwk: unknown }

export type KeyStore = {
  /** Newest first. The first signing-capable key of an alg signs; the rest only verify (NFR-S7). */
  list(): Promise<ActiveKey[]>
}

/** Replay protection for one-time values: `jti`, DPoP proofs, upstream nonces (NFR-S5). */
export type ReplayGuard = {
  /** True for exactly one caller while the value is live; false means a replay. Atomic (NFR-S5). */
  claim(namespace: string, value: string, ttl: Seconds): Promise<boolean>
  /** Bounded sweep of lapsed entries: every `jti` and DPoP proof leaves one (NFR-P3). */
  prune?(before: EpochMillis, limit: number): Promise<number>
}

export type LinkedIdentityStore = EntityStore<LinkedIdentity, [upstream: string, subject: string]> & {
  listForAccount(accountId: string): Promise<LinkedIdentity[]>
}

/** A username is unique, so it changes through `upsert`, which refuses one another account holds, never through `update`. */
export type CredentialStore = UpdatableStore<Credential, 'accountId' | 'username'> & {
  findByUsername(username: string): Promise<Credential | undefined>
  /** Writes only when neither the account nor the username exists, atomically: two sign-ups racing for one name must not both win. */
  create(credential: Credential): Promise<boolean>
}

/** Keyed by credential id, which the authenticator chooses: an assertion names its credential, not its account. */
export type PasskeyStore = UpdatableStore<Passkey, 'accountId' | 'credentialId'> & {
  listForAccount(accountId: string): Promise<Passkey[]>
  /** Writes only when the credential id is free, atomically: a credential registered to one account is never moved to another (FR-I8). */
  create(passkey: Passkey): Promise<boolean>
}

export type RealmStore = EntityStore<Realm> & {
  list(): Promise<Realm[]>
  /** Writes only when the id is free, atomically: two operators creating one realm must not both win. */
  create(realm: Realm): Promise<boolean>
}
