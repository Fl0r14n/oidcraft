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
  PasskeyStore,
  RealmStore,
  ReplayGuard
} from './adapter'
import { mergedGrant } from './grants'
import { page } from './page'
import type { Artifact, Client, Credential, Grant, LinkedIdentity, Passkey, Realm, Seconds, Session } from './types'

export type KvEntry = { key: string; value: string; ttl?: Seconds }

/** The minimum a new backend has to implement; `fromKv` builds a full `Adapter` over it. */
export type KvStore = EntityStore<KvEntry, [key: string]> & {
  /**
   * Writes only when the key holds no live entry, atomically, and resolves whether it wrote. Single use rests on it,
   * so an eventually consistent store cannot back a provider (FR-A3).
   */
  create(entry: KvEntry): Promise<boolean>
  /** Deletes the entry only while it holds this value, atomically, and resolves whether it deleted: a lock's release rests on it. */
  destroyIf(key: string, value: string): Promise<boolean>
  /** Prefix scan, for range deletes like grant revocation; it must cost what it matches, not the store's size: requests use it (NFR-P1). */
  scan(prefix: string): AsyncIterable<KvEntry>
}

export type FromKvOptions = {
  keys: KeyStore
  /** Omitted, every account lookup misses: the host composes one in later, as `@oidcraft/provider/accounts` does. */
  accounts?: AccountStore
}

/** Every account lookup misses, until the host composes its own store in. */
export const noAccounts: AccountStore = {
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

const secondsUntil = (expiresAt: Date): Seconds => Math.max(1, Math.ceil((expiresAt.getTime() - Date.now()) / 1000))

const collect = async <T>(kv: KvStore, prefix: string, revived: (raw: string) => T) => {
  const out: T[] = []
  for await (const { value } of kv.scan(prefix)) out.push(revived(value))
  return out
}

const LOCK_TTL: Seconds = 5
const LOCK_RETRY_MS = 25
const LOCK_WAITS = (LOCK_TTL * 1000) / LOCK_RETRY_MS + 1

// An id may hold a slash — a client id is a URL — and a slash is what ends a prefix.
const part = (id: string) => encodeURIComponent(id)

/** A full `Adapter` over a `KvStore` (FR-A3): each index is a key beside its record, so no request scans a whole family (NFR-P1, FR-A5). */
export const fromKv = (kv: KvStore, options: FromKvOptions): FullAdapter => {
  const read = async (key: string) => (await kv.find(key))?.value
  const under = async (prefix: string) => {
    const ids: string[] = []
    for await (const { key } of kv.scan(prefix)) ids.push(decodeURIComponent(key.slice(prefix.length)))
    return ids
  }
  const present = <T>(values: (T | undefined)[]) => values.filter((value): value is T => value !== undefined)

  /** A store with no compare-and-swap serializes writers to one record by an atomic create, released when done. */
  const locked = async <T>(lock: string, run: () => Promise<T>) => {
    const owner = crypto.randomUUID()
    for (let wait = 0; wait < LOCK_WAITS; wait++) {
      if (await kv.create({ key: lock, value: owner, ttl: LOCK_TTL })) {
        try {
          return await run()
        } finally {
          // Past LOCK_TTL the lock may be the next writer's, so only this one's own is released.
          await kv.destroyIf(lock, owner)
        }
      }
      await new Promise(resolve => setTimeout(resolve, LOCK_RETRY_MS))
    }
    throw new Error(`${lock} stayed locked`)
  }
  const artifactKey = (kind: string, id: string) => `artifact/${kind}/${id}`
  const clientArtifacts = (clientId: string) => `client-artifact/${part(clientId)}/`
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
      const ttl = secondsUntil(artifact.expiresAt)
      await kv.upsert({ key: artifactKey(artifact.kind, artifact.id), value: enc(stored), ttl })
      if (artifact.grantId) await kv.upsert({ key: `grant-index/${artifact.grantId}/${artifact.kind}/${artifact.id}`, value: '', ttl })
      if (artifact.familyId) await kv.upsert({ key: `family-index/${artifact.familyId}/${artifact.kind}/${artifact.id}`, value: '', ttl })
      await kv.upsert({ key: `${clientArtifacts(artifact.clientId)}${artifact.kind}/${artifact.id}`, value: '', ttl })
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
      if (!(await kv.create({ key: consumedKey(kind, id), value: new Date().toISOString(), ttl: secondsUntil(expiresAt) }))) return false
      // Deleted between the read and the create, it is revoked, not redeemed (NFR-S4).
      return (await read(artifactKey(kind, id))) !== undefined
    },

    async destroy(kind, id) {
      await kv.destroy(artifactKey(kind, id))
    },

    async destroyByGrantId(grantId) {
      for await (const { key } of kv.scan(`grant-index/${grantId}/`)) {
        const [, , kind, id] = key.split('/')
        if (kind && id) await kv.destroy(artifactKey(kind, id))
        await kv.destroy(key)
      }
    },

    async destroyByFamilyId(familyId) {
      for await (const { key } of kv.scan(`family-index/${familyId}/`)) {
        const [, , kind, id] = key.split('/')
        if (kind && id) await kv.destroy(artifactKey(kind, id))
        await kv.destroy(key)
      }
    },

    // R-1: RFC 7592 lets any registered client delete itself, so this reads its own index, never every artifact (NFR-P1).
    async destroyByClientId(clientId) {
      for await (const { key } of kv.scan(clientArtifacts(clientId))) {
        const [kind, id] = key.slice(clientArtifacts(clientId).length).split('/')
        if (kind && id) await kv.destroy(artifactKey(kind, id))
        await kv.destroy(key)
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

  // Each added client is its own key, so concurrent sign-ins cannot lose a race rewriting one list (FR-C11).
  const sessionClientPrefix = (id: string) => `session-client/${id}/`
  const withClients = async (session: Session) => {
    const added: string[] = []
    for await (const { key } of kv.scan(sessionClientPrefix(session.id))) added.push(key.slice(sessionClientPrefix(session.id).length))
    return { ...session, clients: [...new Set([...session.clients, ...added])] }
  }
  // Index keys beside the session, so a lookup by account or upstream session never reads every session (NFR-P1).
  const accountSessions = (accountId: string) => `account-session/${part(accountId)}/`
  const upstreamSessions = (provider: string, upstreamSessionId: string) => `upstream-session/${part(provider)}/${part(upstreamSessionId)}/`
  const sessionIndexes = (session: Session) => [
    `${accountSessions(session.accountId)}${part(session.id)}`,
    ...(session.idp && session.upstreamSessionId ? [`${upstreamSessions(session.idp, session.upstreamSessionId)}${part(session.id)}`] : [])
  ]
  const sessionLock = (id: string) => `session-lock/${part(id)}`
  const writeSession = async (session: Session) => {
    const ttl = secondsUntil(session.expiresAt)
    await kv.upsert({ key: `session/${session.id}`, value: enc(session), ttl })
    for (const key of sessionIndexes(session)) await kv.upsert({ key, value: '', ttl })
  }
  const readSession = async (id: string) => {
    const session = dec<Session>(await read(`session/${id}`))
    return session && revive(session, ['authTime', 'expiresAt', 'lastUsedAt'])
  }

  const sessions: BrokeringAdapter['sessions'] = {
    async find(id) {
      const live = await readSession(id)
      return live && live.expiresAt.getTime() > Date.now() ? withClients(live) : undefined
    },
    async listForAccount(accountId) {
      return present(await Promise.all((await under(accountSessions(accountId))).map(id => sessions.find(id))))
    },
    async listByUpstreamSession(provider, upstreamSessionId) {
      return present(await Promise.all((await under(upstreamSessions(provider, upstreamSessionId))).map(id => sessions.find(id))))
    },
    async addClient(id, clientId) {
      const session = await readSession(id)
      if (!session) return
      await kv.upsert({ key: `${sessionClientPrefix(id)}${clientId}`, value: '', ttl: secondsUntil(session.expiresAt) })
    },
    upsert: session => locked(sessionLock(session.id), () => writeSession(session)),
    // Under the record's lock, so an update racing it cannot write an ended session back.
    destroy: id =>
      locked(sessionLock(id), async () => {
        const session = await readSession(id)
        await kv.destroy(`session/${id}`)
        for (const key of session ? sessionIndexes(session) : []) await kv.destroy(key)
        for await (const { key } of kv.scan(sessionClientPrefix(id))) await kv.destroy(key)
      }),
    update: (id, fields) =>
      locked(sessionLock(id), async () => {
        const session = await readSession(id)
        if (!session || session.expiresAt.getTime() <= Date.now()) return false
        const { id: _, clients: __, ...changed } = fields as Partial<Session>
        const next = { ...session, ...changed }
        for (const key of sessionIndexes(session)) if (!sessionIndexes(next).includes(key)) await kv.destroy(key)
        await writeSession(next)
        return true
      })
  }

  // The pair is its own key, so the grant lookup every authorization makes reads one key (NFR-P1).
  const accountGrants = (accountId: string) => `grant-by/${part(accountId)}/`
  const grantIndex = (grant: Pick<Grant, 'accountId' | 'clientId'>) => `${accountGrants(grant.accountId)}${part(grant.clientId)}`
  const clientGrants = (clientId: string) => `grant-by-client/${part(clientId)}/`
  const readGrant = async (id: string) => {
    const grant = dec<Grant>(await read(`grant/${id}`))
    const live = grant && revive(grant, ['createdAt', 'expiresAt'])
    // FR-T5: a TTL rounds up to a second, so the expiry is checked as an artifact's is.
    return live && (!live.expiresAt || live.expiresAt.getTime() > Date.now()) ? live : undefined
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
      const ttl = grant.expiresAt && { ttl: secondsUntil(grant.expiresAt) }
      const claimed = await kv.create({ key: grantIndex(grant), value: grant.id, ...ttl })
      const id = claimed ? grant.id : ((await read(grantIndex(grant))) ?? grant.id)
      const held = id === grant.id ? undefined : await readGrant(id)
      // R-8: the pair's grant takes what is written, as SQL's upsert does; adding to it is `merge`'s, under its lock (FR-I4).
      const stored = held ? { ...grant, id, createdAt: held.createdAt } : { ...grant, id }
      await kv.upsert({ key: `grant/${id}`, value: enc(stored), ...ttl })
      await kv.upsert({ key: grantIndex(grant), value: id, ...ttl })
      await kv.upsert({ key: `${clientGrants(grant.clientId)}${part(id)}`, value: id, ...ttl })
    },
    // FR-I4: a store with no compare-and-swap serializes consents to one pair by an atomic create, released when done.
    merge: grant =>
      locked(`grant-lock/${part(grant.accountId)}/${part(grant.clientId)}`, async () => {
        const id = await read(grantIndex(grant))
        const held = id === undefined ? undefined : await readGrant(id)
        if (id !== undefined && !held) {
          await kv.destroy(`grant/${id}`)
          await kv.destroy(grantIndex(grant))
        }
        const stored = held ? mergedGrant(held, grant) : grant
        await grants.upsert(stored)
        return stored
      }),
    async destroy(id) {
      const grant = await readGrant(id)
      await kv.destroy(`grant/${id}`)
      // Only its own pointer: a later grant for the same pair may have taken the key over.
      if (grant) await kv.destroyIf(grantIndex(grant), id)
      if (grant) await kv.destroy(`${clientGrants(grant.clientId)}${part(id)}`)
    },
    // R-1: by the client's own index, as its artifacts are, never by reading every grant.
    async destroyByClientId(clientId) {
      for await (const { key, value } of kv.scan(clientGrants(clientId))) {
        await grants.destroy(value)
        await kv.destroy(key)
      }
    }
  }

  const replay: ReplayGuard = {
    async claim(namespace, value, ttl) {
      return kv.create({ key: `replay/${namespace}/${value}`, value: '1', ttl })
    }
  }

  const identityKey = (provider: string, subject: string) => `identity/${part(provider)}/${part(subject)}`
  const identities: LinkedIdentityStore = {
    async find(upstream, subject) {
      const identity = dec<LinkedIdentity>(await read(identityKey(upstream, subject)))
      return identity ? revive(identity, ['createdAt']) : undefined
    },
    async listForAccount(accountId) {
      const all = await collect(kv, 'identity/', raw => revive(JSON.parse(raw) as LinkedIdentity, ['createdAt']))
      return all.filter(identity => identity.accountId === accountId)
    },
    async upsert(identity) {
      await kv.upsert({ key: identityKey(identity.upstream, identity.subject), value: enc(identity) })
    },
    async destroy(upstream, subject) {
      await kv.destroy(identityKey(upstream, subject))
    }
  }

  const credentialKey = (accountId: string) => `credential/${accountId}`
  const usernameKey = (username: string) => `username/${username}`
  const credentialLock = (accountId: string) => `credential-lock/${part(accountId)}`
  const reviveCredential = (credential: Credential) => {
    revive(credential, ['createdAt', 'updatedAt', 'lockedUntil'])
    if (credential.totp) revive(credential.totp, ['confirmedAt'])
    return credential
  }
  const readCredential = async (accountId: string) => {
    const credential = dec<Credential>(await read(credentialKey(accountId)))
    return credential ? reviveCredential(credential) : undefined
  }

  // The username index is claimed with `create`, so uniqueness rests on the same atomic write as single use.
  const credentials: CredentialStore = {
    find: readCredential,
    async findByUsername(username) {
      const accountId = await read(usernameKey(username))
      return accountId ? readCredential(accountId) : undefined
    },
    async create(credential) {
      if (!(await kv.create({ key: usernameKey(credential.username), value: credential.accountId }))) return false
      if (await kv.create({ key: credentialKey(credential.accountId), value: enc(credential) })) return true
      await kv.destroy(usernameKey(credential.username))
      return false
    },
    upsert: credential =>
      locked(credentialLock(credential.accountId), async () => {
        const existing = await readCredential(credential.accountId)
        if (existing && existing.username !== credential.username) {
          if (!(await kv.create({ key: usernameKey(credential.username), value: credential.accountId }))) {
            throw new Error(`the username ${credential.username} is taken`)
          }
          await kv.destroy(usernameKey(existing.username))
        }
        await kv.upsert({ key: credentialKey(credential.accountId), value: enc(credential) })
      }),
    destroy: accountId =>
      locked(credentialLock(accountId), async () => {
        const existing = await readCredential(accountId)
        if (existing) await kv.destroy(usernameKey(existing.username))
        await kv.destroy(credentialKey(accountId))
      }),
    update: (accountId, fields) =>
      locked(credentialLock(accountId), async () => {
        const existing = await readCredential(accountId)
        if (!existing) return false
        const { accountId: _, username: __, ...changed } = fields as Partial<Credential>
        await kv.upsert({ key: credentialKey(accountId), value: enc({ ...existing, ...changed }) })
        return true
      })
  }

  // The credential id is the authenticator's choice, so it is escaped like any other id that is not ours.
  const passkeyKey = (credentialId: string) => `passkey/${part(credentialId)}`
  const accountPasskeys = (accountId: string) => `account-passkey/${part(accountId)}/`
  const passkeyLock = (credentialId: string) => `passkey-lock/${part(credentialId)}`
  const readPasskey = async (credentialId: string) => {
    const passkey = dec<Passkey>(await read(passkeyKey(credentialId)))
    return passkey ? revive(passkey, ['createdAt', 'lastUsedAt']) : undefined
  }

  const passkeys: PasskeyStore = {
    find: readPasskey,
    async listForAccount(accountId) {
      return present(await Promise.all((await under(accountPasskeys(accountId))).map(readPasskey))).filter(
        passkey => passkey.accountId === accountId
      )
    },
    async create(passkey) {
      if (!(await kv.create({ key: passkeyKey(passkey.credentialId), value: enc(passkey) }))) return false
      await kv.upsert({ key: `${accountPasskeys(passkey.accountId)}${part(passkey.credentialId)}`, value: '' })
      return true
    },
    upsert: passkey =>
      locked(passkeyLock(passkey.credentialId), async () => {
        await kv.upsert({ key: passkeyKey(passkey.credentialId), value: enc(passkey) })
        await kv.upsert({ key: `${accountPasskeys(passkey.accountId)}${part(passkey.credentialId)}`, value: '' })
      }),
    destroy: credentialId =>
      locked(passkeyLock(credentialId), async () => {
        const passkey = await readPasskey(credentialId)
        await kv.destroy(passkeyKey(credentialId))
        if (passkey) await kv.destroy(`${accountPasskeys(passkey.accountId)}${part(credentialId)}`)
      }),
    update: (credentialId, fields) =>
      locked(passkeyLock(credentialId), async () => {
        const passkey = await readPasskey(credentialId)
        if (!passkey) return false
        const { accountId: _, credentialId: __, ...changed } = fields as Partial<Passkey>
        await kv.upsert({ key: passkeyKey(credentialId), value: enc({ ...passkey, ...changed }) })
        return true
      })
  }

  const realmKey = (id: string) => `realm/${id}`
  const reviveRealm = (raw: string) => revive(JSON.parse(raw) as Realm, ['createdAt', 'updatedAt'])
  const realms: RealmStore = {
    async find(id) {
      const raw = await read(realmKey(id))
      return raw === undefined ? undefined : reviveRealm(raw)
    },
    list: () => collect(kv, 'realm/', reviveRealm),
    create: realm => kv.create({ key: realmKey(realm.id), value: enc(realm) }),
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
    passkeys,
    realms,
    keys: options.keys,
    replay,
    identities
  }
}
