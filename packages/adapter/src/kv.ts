import type {
  AccountStore,
  ArtifactStore,
  BrokeringAdapter,
  ClientStore,
  CredentialStore,
  EntityStore,
  FullAdapter,
  GrantStore,
  KeyStore,
  LinkedIdentityStore,
  RealmStore,
  ReplayGuard
} from './adapter'
import { page } from './page'
import type { Artifact, Client, Credential, Grant, LinkedIdentity, Realm, Seconds, Session } from './types'

export type KvEntry = { key: string; value: string; ttl?: Seconds }

/** The minimum a new backend has to implement; `fromKv` builds a full `Adapter` over it. */
export type KvStore = EntityStore<KvEntry, [key: string]> & {
  /**
   * Writes only when the key holds no live entry, atomically, and resolves whether it wrote. Single
   * use is built on it, so a store that cannot do it (an eventually consistent one) cannot back a
   * provider (FR-A3).
   */
  insert(entry: KvEntry): Promise<boolean>
  /**
   * Prefix scan. Required because grant revocation is a range delete, not a point delete. It should
   * cost what it matches, not what the store holds: `fromKv` scans one record's keys on a request
   * path, and a store that walks everything to find them makes every request that slow (NFR-P1).
   */
  scan(prefix: string): AsyncIterable<KvEntry>
}

export type FromKvOptions = {
  keys: KeyStore
  /** Omitted, every account lookup misses: the host composes one in later, as `@oidcraft/provider/accounts` does. */
  accounts?: AccountStore
}

const noAccounts: AccountStore = {
  async find() {
    return undefined
  },
  async claims() {
    return undefined
  }
}

const enc = (value: unknown) => JSON.stringify(value)

const dec = <T>(raw: string | undefined): T | undefined => (raw === undefined ? undefined : (JSON.parse(raw) as T))

const revive = <T>(value: T, dates: (keyof T & string)[]) => {
  const record = value as Record<string, unknown>
  for (const field of dates) {
    if (typeof record[field] === 'string') record[field] = new Date(record[field] as string)
  }
  return value
}

const ttlFrom = (expiresAt: Date): Seconds => Math.max(1, Math.ceil((expiresAt.getTime() - Date.now()) / 1000))

const collect = async <T>(kv: KvStore, prefix: string, revived: (raw: string) => T) => {
  const out: T[] = []
  for await (const { value } of kv.scan(prefix)) out.push(revived(value))
  return out
}

// An id may hold a slash — a client id is a URL — and a slash is what ends a prefix.
const part = (id: string) => encodeURIComponent(id)

/**
 * A complete `Adapter` over a `KvStore` (FR-A3), whose atomic `insert` every single-use rule rests on.
 *
 * A key-value store has no secondary index, so each one the protocol needs is a key beside the
 * record, and a lookup is a prefix scan of one record's keys. A request path never scans a whole
 * family of records (NFR-P1); a relational adapter uses real columns instead (FR-A5).
 */

export const fromKv = (kv: KvStore, options: FromKvOptions): FullAdapter => {
  const read = async (key: string) => (await kv.find(key))?.value
  // The last segment of each key under a prefix: how a record's index is read back (NFR-P1).
  const under = async (prefix: string) => {
    const ids: string[] = []
    for await (const { key } of kv.scan(prefix)) ids.push(decodeURIComponent(key.slice(prefix.length)))
    return ids
  }
  const present = <T>(values: (T | undefined)[]) => values.filter((value): value is T => value !== undefined)
  const artifactKey = (kind: string, id: string) => `artifact/${kind}/${id}`
  // Kept apart from the artifact so an upsert cannot overwrite it (FR-T3, NFR-S4).
  const consumedKey = (kind: string, id: string) => `consumed/${kind}/${id}`
  const withConsumption = async (artifact: Artifact) => {
    const consumedAt = await read(consumedKey(artifact.kind, artifact.id))
    const { consumedAt: _, ...rest } = revive(artifact, ['expiresAt'])
    return consumedAt ? { ...rest, consumedAt: new Date(consumedAt) } : rest
  }

  const artifacts: ArtifactStore = {
    async upsert(artifact) {
      const { consumedAt: _, ...stored } = artifact
      const ttl = ttlFrom(artifact.expiresAt)
      await kv.upsert({ key: artifactKey(artifact.kind, artifact.id), value: enc(stored), ttl })
      if (artifact.grantId) await kv.upsert({ key: `grant-index/${artifact.grantId}/${artifact.kind}/${artifact.id}`, value: '', ttl })
      if (typeof artifact.payload.userCode === 'string') {
        await kv.upsert({ key: `user-code/${artifact.payload.userCode}`, value: artifactKey(artifact.kind, artifact.id), ttl })
      }
    },

    async find(kind, id) {
      const artifact = dec<Artifact>(await read(artifactKey(kind, id)))
      if (!artifact) return undefined
      const live = await withConsumption(artifact)
      // FR-T5: an expiry the store missed must still not be served.
      return live.expiresAt.getTime() > Date.now() ? live : undefined
    },

    async findByUserCode(userCode) {
      const pointer = await read(`user-code/${userCode}`)
      if (!pointer) return undefined
      const artifact = dec<Artifact>(await read(pointer))
      if (!artifact) return undefined
      const live = await withConsumption(artifact)
      return live.expiresAt.getTime() > Date.now() ? live : undefined
    },

    async consume(kind, id) {
      const artifact = dec<Artifact>(await read(artifactKey(kind, id)))
      if (!artifact) return false
      const expiresAt = new Date(artifact.expiresAt)
      if (expiresAt.getTime() <= Date.now()) return false
      return kv.insert({ key: consumedKey(kind, id), value: new Date().toISOString(), ttl: ttlFrom(expiresAt) })
    },

    async destroy(kind, id) {
      await kv.destroy(artifactKey(kind, id))
    },

    async revokeByGrantId(grantId) {
      for await (const { key } of kv.scan(`grant-index/${grantId}/`)) {
        const [, , kind, id] = key.split('/')
        if (kind && id) await kv.destroy(artifactKey(kind, id))
        await kv.destroy(key)
      }
    },

    // A scan of every artifact: deleting a client is rare and an operator's, so it is not worth an index key per write.
    async revokeByClientId(clientId) {
      for await (const { key, value } of kv.scan('artifact/')) {
        if (dec<Artifact>(value)?.clientId === clientId) await kv.destroy(key)
      }
    }
  }

  const clients: ClientStore = {
    async find(clientId) {
      const client = dec<Record<string, unknown>>(await read(`client/${clientId}`))
      return client ? (revive(client, ['createdAt', 'updatedAt']) as never) : undefined
    },
    async upsert(client) {
      await kv.upsert({ key: `client/${client.clientId}`, value: enc(client) })
    },
    async destroy(clientId) {
      await kv.destroy(`client/${clientId}`)
    },
    async list(cursor, limit) {
      const all: Client[] = await collect(kv, 'client/', raw => revive(JSON.parse(raw), ['createdAt', 'updatedAt']) as never)
      return page(
        all.filter(client => cursor === undefined || client.clientId > cursor).sort((a, b) => (a.clientId < b.clientId ? -1 : 1)),
        limit
      )
    }
  }

  // Each added client is its own key: an upsert of a key nobody else writes cannot lose a race,
  // where rewriting the session's list could (FR-C11).
  const sessionClientPrefix = (id: string) => `session-client/${id}/`
  const withClients = async (session: Session) => {
    const added: string[] = []
    for await (const { key } of kv.scan(sessionClientPrefix(session.id))) added.push(key.slice(sessionClientPrefix(session.id).length))
    return { ...session, clients: [...new Set([...session.clients, ...added])] }
  }
  // Index keys beside the session, so a lookup by account or upstream session reads those and not every session (NFR-P1).
  const accountSessions = (accountId: string) => `account-session/${part(accountId)}/`
  const upstreamSessions = (provider: string, upstreamSessionId: string) => `upstream-session/${part(provider)}/${part(upstreamSessionId)}/`
  const sessionIndexes = (session: Session) => [
    `${accountSessions(session.accountId)}${part(session.id)}`,
    ...(session.idp && session.upstreamSessionId ? [`${upstreamSessions(session.idp, session.upstreamSessionId)}${part(session.id)}`] : [])
  ]
  const readSession = async (id: string) => {
    const session = dec<Session>(await read(`session/${id}`))
    return session && revive(session, ['authTime', 'expiresAt'])
  }

  const sessions: BrokeringAdapter['sessions'] = {
    async find(id) {
      const live = await readSession(id)
      return live && live.expiresAt.getTime() > Date.now() ? withClients(live) : undefined
    },
    async listForAccount(accountId) {
      return present(await Promise.all((await under(accountSessions(accountId))).map(id => sessions.find(id))))
    },
    async findByUpstreamSession(provider, upstreamSessionId) {
      return present(await Promise.all((await under(upstreamSessions(provider, upstreamSessionId))).map(id => sessions.find(id))))
    },
    async addClient(id, clientId) {
      const session = await readSession(id)
      if (!session) return
      await kv.upsert({ key: `${sessionClientPrefix(id)}${clientId}`, value: '', ttl: ttlFrom(session.expiresAt) })
    },
    async upsert(session) {
      const ttl = ttlFrom(session.expiresAt)
      await kv.upsert({ key: `session/${session.id}`, value: enc(session), ttl })
      for (const key of sessionIndexes(session)) await kv.upsert({ key, value: '', ttl })
    },
    async destroy(id) {
      const session = await readSession(id)
      await kv.destroy(`session/${id}`)
      for (const key of session ? sessionIndexes(session) : []) await kv.destroy(key)
      for await (const { key } of kv.scan(sessionClientPrefix(id))) await kv.destroy(key)
    }
  }

  // The pair is a key of its own, and an account's grants a prefix: the grant lookup every authorization makes reads one key (NFR-P1).
  const accountGrants = (accountId: string) => `grant-by/${part(accountId)}/`
  const grantIndex = (grant: Pick<Grant, 'accountId' | 'clientId'>) => `${accountGrants(grant.accountId)}${part(grant.clientId)}`
  const readGrant = async (id: string) => {
    const grant = dec<Grant>(await read(`grant/${id}`))
    return grant && revive(grant, ['createdAt', 'expiresAt'])
  }

  const grants: GrantStore = {
    find: readGrant,
    async findByAccountAndClient(accountId, clientId) {
      const id = await read(grantIndex({ accountId, clientId }))
      return id === undefined ? undefined : readGrant(id)
    },
    async listForAccount(accountId) {
      const ids: string[] = []
      for await (const { value } of kv.scan(accountGrants(accountId))) ids.push(value)
      return present(await Promise.all(ids.map(readGrant)))
    },
    async upsert(grant) {
      const ttl = grant.expiresAt && { ttl: ttlFrom(grant.expiresAt) }
      await kv.upsert({ key: `grant/${grant.id}`, value: enc(grant), ...ttl })
      await kv.upsert({ key: grantIndex(grant), value: grant.id, ...ttl })
    },
    async destroy(id) {
      const grant = await readGrant(id)
      await kv.destroy(`grant/${id}`)
      // Only its own pointer: a later grant for the same pair may have taken the key over.
      if (grant && (await read(grantIndex(grant))) === id) await kv.destroy(grantIndex(grant))
    },
    // A scan of every grant: deleting a client is rare and an operator's.
    async destroyByClientId(clientId) {
      for await (const { value } of kv.scan('grant/')) {
        const grant = dec<Grant>(value)
        if (grant?.clientId === clientId) await grants.destroy(grant.id)
      }
    }
  }

  const replay: ReplayGuard = {
    async claim(namespace, value, ttl) {
      return kv.insert({ key: `replay/${namespace}/${value}`, value: '1', ttl })
    }
  }

  const identities: LinkedIdentityStore = {
    async find(provider, subject) {
      const identity = dec<LinkedIdentity>(await read(`identity/${provider}/${subject}`))
      return identity ? revive(identity, ['linkedAt']) : undefined
    },
    async listForAccount(accountId) {
      const all = await collect(kv, 'identity/', raw => revive(JSON.parse(raw) as LinkedIdentity, ['linkedAt']))
      return all.filter(identity => identity.accountId === accountId)
    },
    async upsert(identity) {
      await kv.upsert({ key: `identity/${identity.provider}/${identity.subject}`, value: enc(identity) })
    },
    async destroy(provider, subject) {
      await kv.destroy(`identity/${provider}/${subject}`)
    }
  }

  const credentialKey = (accountId: string) => `credential/${accountId}`
  const usernameKey = (username: string) => `username/${username}`
  const reviveCredential = (credential: Credential) => {
    revive(credential, ['createdAt', 'updatedAt', 'lockedUntil'])
    if (credential.totp) revive(credential.totp, ['confirmedAt'])
    return credential
  }
  const readCredential = async (accountId: string) => {
    const credential = dec<Credential>(await read(credentialKey(accountId)))
    return credential ? reviveCredential(credential) : undefined
  }

  // The username index is claimed with `insert`, so uniqueness rests on the same atomic write as single use.
  const credentials: CredentialStore = {
    find: readCredential,
    async findByUsername(username) {
      const accountId = await read(usernameKey(username))
      return accountId ? readCredential(accountId) : undefined
    },
    async create(credential) {
      if (!(await kv.insert({ key: usernameKey(credential.username), value: credential.accountId }))) return false
      if (await kv.insert({ key: credentialKey(credential.accountId), value: enc(credential) })) return true
      await kv.destroy(usernameKey(credential.username))
      return false
    },
    async upsert(credential) {
      const existing = await readCredential(credential.accountId)
      if (existing && existing.username !== credential.username) {
        if (!(await kv.insert({ key: usernameKey(credential.username), value: credential.accountId }))) {
          throw new Error(`the username ${credential.username} is taken`)
        }
        await kv.destroy(usernameKey(existing.username))
      }
      await kv.upsert({ key: credentialKey(credential.accountId), value: enc(credential) })
    },
    async destroy(accountId) {
      const existing = await readCredential(accountId)
      if (existing) await kv.destroy(usernameKey(existing.username))
      await kv.destroy(credentialKey(accountId))
    }
  }

  const realmKey = (id: string) => `realm/${id}`
  const reviveRealm = (raw: string) => revive(JSON.parse(raw) as Realm, ['createdAt', 'updatedAt'])
  const realms: RealmStore = {
    async find(id) {
      const raw = await read(realmKey(id))
      return raw === undefined ? undefined : reviveRealm(raw)
    },
    list: () => collect(kv, 'realm/', reviveRealm),
    create: realm => kv.insert({ key: realmKey(realm.id), value: enc(realm) }),
    async upsert(realm) {
      await kv.upsert({ key: realmKey(realm.id), value: enc(realm) })
    },
    async destroy(id) {
      await kv.destroy(realmKey(id))
    }
  }

  return {
    clients,
    artifacts,
    sessions,
    grants,
    accounts: options.accounts ?? noAccounts,
    credentials,
    realms,
    keys: options.keys,
    replay,
    identities
  }
}
