import type {
  AccountStore,
  Artifact,
  ArtifactKind,
  Client,
  Credential,
  FullAdapter,
  Grant,
  KeyStore,
  LinkedIdentity,
  Realm,
  Session
} from 'oidcraft'
import { type DataSource, type EntitySchema, QueryFailedError, type Repository } from 'typeorm'
import {
  ArtifactEntity,
  type ArtifactRow,
  ClientEntity,
  CredentialEntity,
  type CredentialRow,
  GrantEntity,
  type GrantRow,
  IdentityEntity,
  type IdentityRow,
  OIDCRAFT_ENTITIES,
  RealmEntity,
  type RealmRow,
  ReplayEntity,
  SessionEntity,
  type SessionRow
} from './schema'

export type TypeormAdapterOptions = {
  /** Initialized, with `OIDCRAFT_ENTITIES` among its entities and the migrations already run. */
  dataSource: DataSource
  keys: KeyStore
  /** Omitted, every account lookup misses: the host composes one in later, as `oidcraft/accounts` does. */
  accounts?: AccountStore
}

const now = () => Date.now()
const json = (value: unknown) => JSON.stringify(value)
const parse = <T>(value: string) => JSON.parse(value) as T

const toArtifact = (row: ArtifactRow): Artifact => ({
  id: row.id,
  kind: row.kind as ArtifactKind,
  clientId: row.client_id,
  ...(row.account_id && { accountId: row.account_id }),
  ...(row.grant_id && { grantId: row.grant_id }),
  payload: parse<Record<string, unknown>>(row.payload),
  ...(row.consumed_at && { consumedAt: new Date(row.consumed_at) }),
  expiresAt: new Date(row.expires_at)
})

const toSession = (row: SessionRow): Session => ({
  id: row.id,
  accountId: row.account_id,
  authTime: new Date(row.auth_time),
  ...(row.acr && { acr: row.acr }),
  ...(row.amr ? { amr: parse<string[]>(row.amr) } : {}),
  ...(row.idp && { idp: row.idp }),
  ...(row.upstream_session_id && { upstreamSessionId: row.upstream_session_id }),
  clients: parse<string[]>(row.clients),
  expiresAt: new Date(row.expires_at)
})

const toGrant = (row: GrantRow): Grant => ({
  id: row.id,
  accountId: row.account_id,
  clientId: row.client_id,
  scopes: parse<string[]>(row.scopes),
  claims: parse<string[]>(row.claims),
  resources: parse<Record<string, string[]>>(row.resources),
  createdAt: new Date(row.created_at),
  ...(row.expires_at && { expiresAt: new Date(row.expires_at) })
})

const credentialRow = (credential: Credential): CredentialRow => ({
  account_id: credential.accountId,
  username: credential.username,
  password_hash: credential.passwordHash,
  claims: json(credential.claims),
  totp_secret: credential.totp?.secret ?? null,
  totp_confirmed_at: credential.totp?.confirmedAt?.getTime() ?? null,
  recovery_codes: credential.recoveryCodes ? json(credential.recoveryCodes) : null,
  failed_attempts: credential.failedAttempts,
  locked_until: credential.lockedUntil?.getTime() ?? null,
  created_at: credential.createdAt.getTime(),
  updated_at: credential.updatedAt.getTime()
})

const toCredential = (row: CredentialRow): Credential => ({
  accountId: row.account_id,
  username: row.username,
  passwordHash: row.password_hash,
  claims: parse<Record<string, unknown>>(row.claims),
  ...(row.totp_secret && {
    totp: { secret: row.totp_secret, ...(row.totp_confirmed_at && { confirmedAt: new Date(row.totp_confirmed_at) }) }
  }),
  ...(row.recovery_codes ? { recoveryCodes: parse<string[]>(row.recovery_codes) } : {}),
  failedAttempts: row.failed_attempts,
  ...(row.locked_until && { lockedUntil: new Date(row.locked_until) }),
  createdAt: new Date(row.created_at),
  updatedAt: new Date(row.updated_at)
})

const toIdentity = (row: IdentityRow): LinkedIdentity => ({
  accountId: row.account_id,
  provider: row.provider,
  subject: row.subject,
  ...(row.email && { email: row.email }),
  claims: parse<Record<string, unknown>>(row.claims),
  linkedAt: new Date(row.linked_at)
})

const realmRow = (realm: Realm): RealmRow => ({
  id: realm.id,
  display_name: realm.displayName ?? null,
  enabled: realm.enabled ? 1 : 0,
  settings: json(realm.settings),
  created_at: realm.createdAt.getTime(),
  updated_at: realm.updatedAt.getTime()
})

const toRealm = (row: RealmRow): Realm => ({
  id: row.id,
  ...(row.display_name && { displayName: row.display_name }),
  enabled: Boolean(row.enabled),
  settings: parse<Record<string, unknown>>(row.settings),
  createdAt: new Date(row.created_at),
  updatedAt: new Date(row.updated_at)
})

const noAccounts: AccountStore = {
  async find() {
    return undefined
  },
  async claims() {
    return undefined
  }
}

const upsert = async <T extends object>(
  repository: Repository<T>,
  row: T,
  conflict: (keyof T & string)[],
  overwrite?: (keyof T & string)[]
) => {
  const columns = overwrite ?? (Object.keys(row) as (keyof T & string)[]).filter(column => !conflict.includes(column))
  await repository.createQueryBuilder().insert().values(row).orUpdate(columns, conflict).execute()
}

/**
 * Insert-if-absent. TypeORM's `orIgnore` does not say whether it wrote, so this inserts and, on a
 * failure, answers false only when the row it collided with is really there — any other error is
 * not a lost race and is rethrown (FR-A3, NFR-S4).
 */
const insertIfAbsent = async <T extends object>(repository: Repository<T>, row: T, collided: () => Promise<boolean>) => {
  try {
    await repository.insert(row as never)
    return true
  } catch (error) {
    if (error instanceof QueryFailedError && (await collided())) return false
    throw error
  }
}

/**
 * The same contract as the Drizzle and Kysely adapters, on the host's TypeORM `DataSource` (FR-A6).
 * The queries are dialect-agnostic; the schema shipped and tested is SQLite's, as for the others.
 */
export const typeormAdapter = (options: TypeormAdapterOptions): FullAdapter => {
  const { dataSource } = options
  const missing = OIDCRAFT_ENTITIES.filter(entity => !dataSource.hasMetadata(entity as EntitySchema))
  if (missing.length) {
    throw new Error(
      `the DataSource does not know ${missing.map(entity => entity.options.name).join(', ')}: add OIDCRAFT_ENTITIES to its entities`
    )
  }
  const clients = dataSource.getRepository(ClientEntity)
  const artifactRows = dataSource.getRepository(ArtifactEntity)
  const sessions = dataSource.getRepository(SessionEntity)
  const grants = dataSource.getRepository(GrantEntity)
  const identities = dataSource.getRepository(IdentityEntity)
  const replay = dataSource.getRepository(ReplayEntity)
  const credentials = dataSource.getRepository(CredentialEntity)
  const realms = dataSource.getRepository(RealmEntity)

  const artifacts = {
    async upsert(artifact: Artifact) {
      const row: ArtifactRow = {
        kind: artifact.kind,
        id: artifact.id,
        client_id: artifact.clientId,
        account_id: artifact.accountId ?? null,
        grant_id: artifact.grantId ?? null,
        user_code: (artifact.payload.userCode as string | undefined) ?? null,
        payload: json(artifact.payload),
        consumed_at: artifact.consumedAt ? artifact.consumedAt.getTime() : null,
        expires_at: artifact.expiresAt.getTime()
      }
      // consumed_at is left out of the update: an upsert must never revive a consumed artifact.
      await upsert(artifactRows, row, ['kind', 'id'], ['client_id', 'account_id', 'grant_id', 'user_code', 'payload', 'expires_at'])
    },

    async find(kind: ArtifactKind, id: string) {
      // FR-T5: enforced by the query, so a missed prune still cannot serve an expired token.
      const row = await artifactRows
        .createQueryBuilder('a')
        .where('a.kind = :kind and a.id = :id and a.expires_at > :now', { kind, id, now: now() })
        .getOne()
      return row ? toArtifact(row) : undefined
    },

    async findByUserCode(userCode: string) {
      const row = await artifactRows
        .createQueryBuilder('a')
        .where('a.user_code = :userCode and a.expires_at > :now', { userCode, now: now() })
        .getOne()
      return row ? toArtifact(row) : undefined
    },

    async consume(kind: ArtifactKind, id: string) {
      const result = await artifactRows
        .createQueryBuilder()
        .update()
        .set({ consumed_at: now() })
        .where('kind = :kind and id = :id and consumed_at is null and expires_at > :now', { kind, id, now: now() })
        .execute()
      return result.affected === 1
    },

    async destroy(kind: ArtifactKind, id: string) {
      await artifactRows.delete({ kind, id })
    },

    async revokeByGrantId(grantId: string) {
      // One indexed delete, not a scan (FR-A5).
      await artifactRows.delete({ grant_id: grantId })
    },

    async prune(before: Date, limit: number) {
      const doomed = await artifactRows
        .createQueryBuilder('a')
        .select(['a.kind', 'a.id'])
        .where('a.expires_at <= :before', { before: before.getTime() })
        .limit(limit)
        .getMany()
      for (const row of doomed) await artifacts.destroy(row.kind as ArtifactKind, row.id)
      return doomed.length
    }
  }

  return {
    clients: {
      async find(clientId) {
        const row = await clients.findOneBy({ client_id: clientId })
        if (!row) return undefined
        return { ...parse<Client>(row.data), createdAt: new Date(row.created_at), updatedAt: new Date(row.updated_at) }
      },
      async upsert(client) {
        const row = {
          client_id: client.clientId,
          data: json(client),
          created_at: client.createdAt.getTime(),
          updated_at: client.updatedAt.getTime()
        }
        await upsert(clients, row, ['client_id'], ['data', 'updated_at'])
      },
      async destroy(clientId) {
        await clients.delete({ client_id: clientId })
      },
      async list() {
        const rows = await clients.find()
        return {
          clients: rows.map(row => ({
            ...parse<Client>(row.data),
            createdAt: new Date(row.created_at),
            updatedAt: new Date(row.updated_at)
          }))
        }
      }
    },

    artifacts,

    sessions: {
      async find(id) {
        const row = await sessions.createQueryBuilder('s').where('s.id = :id and s.expires_at > :now', { id, now: now() }).getOne()
        return row ? toSession(row) : undefined
      },
      async listForAccount(accountId) {
        const rows = await sessions
          .createQueryBuilder('s')
          .where('s.account_id = :accountId and s.expires_at > :now', { accountId, now: now() })
          .getMany()
        return rows.map(toSession)
      },
      async findByUpstreamSession(provider, upstreamSessionId) {
        return (await sessions.findBy({ idp: provider, upstream_session_id: upstreamSessionId })).map(toSession)
      },
      async upsert(session) {
        const row: SessionRow = {
          id: session.id,
          account_id: session.accountId,
          auth_time: session.authTime.getTime(),
          acr: session.acr ?? null,
          amr: session.amr ? json(session.amr) : null,
          idp: session.idp ?? null,
          upstream_session_id: session.upstreamSessionId ?? null,
          clients: json(session.clients),
          expires_at: session.expiresAt.getTime()
        }
        await upsert(sessions, row, ['id'])
      },
      // Compare-and-swap on the list just read, retried when another writer won: two clients
      // signing in at once must both be recorded (FR-C11).
      async addClient(id, clientId) {
        for (let attempt = 0; attempt < 64; attempt++) {
          const row = await sessions.findOne({ where: { id }, select: { clients: true } })
          if (!row) return
          const current = parse<string[]>(row.clients)
          if (current.includes(clientId)) return
          const result = await sessions
            .createQueryBuilder()
            .update()
            .set({ clients: json([...current, clientId]) })
            .where('id = :id and clients = :clients', { id, clients: row.clients })
            .execute()
          if (result.affected) return
        }
        throw new Error(`session ${id} kept changing; its client list could not be updated`)
      },
      async destroy(id) {
        await sessions.delete({ id })
      }
    },

    grants: {
      async find(id) {
        const row = await grants.findOneBy({ id })
        return row ? toGrant(row) : undefined
      },
      async findByAccountAndClient(accountId, clientId) {
        const row = await grants.findOneBy({ account_id: accountId, client_id: clientId })
        return row ? toGrant(row) : undefined
      },
      async listForAccount(accountId) {
        return (await grants.findBy({ account_id: accountId })).map(toGrant)
      },
      async upsert(grant) {
        const row: GrantRow = {
          id: grant.id,
          account_id: grant.accountId,
          client_id: grant.clientId,
          scopes: json(grant.scopes),
          claims: json(grant.claims),
          resources: json(grant.resources),
          created_at: grant.createdAt.getTime(),
          expires_at: grant.expiresAt ? grant.expiresAt.getTime() : null
        }
        await upsert(grants, row, ['id'])
      },
      async destroy(id) {
        await grants.delete({ id })
      }
    },

    accounts: options.accounts ?? noAccounts,

    credentials: {
      async find(accountId: string) {
        const row = await credentials.findOneBy({ account_id: accountId })
        return row ? toCredential(row) : undefined
      },
      async findByUsername(username: string) {
        const row = await credentials.findOneBy({ username })
        return row ? toCredential(row) : undefined
      },
      // Both the key and the username are unique; a collision on either is a lost race.
      async create(credential: Credential) {
        return insertIfAbsent(credentials, credentialRow(credential), async () =>
          credentials.exists({ where: [{ account_id: credential.accountId }, { username: credential.username }] })
        )
      },
      async upsert(credential: Credential) {
        await upsert(credentials, credentialRow(credential), ['account_id'])
      },
      async destroy(accountId: string) {
        await credentials.delete({ account_id: accountId })
      }
    },

    realms: {
      async find(id: string) {
        const row = await realms.findOneBy({ id })
        return row ? toRealm(row) : undefined
      },
      async list() {
        return (await realms.find()).map(toRealm)
      },
      async create(realm: Realm) {
        return insertIfAbsent(realms, realmRow(realm), async () => realms.existsBy({ id: realm.id }))
      },
      async upsert(realm: Realm) {
        await upsert(realms, realmRow(realm), ['id'])
      },
      async destroy(id: string) {
        await realms.delete({ id })
      }
    },

    keys: options.keys,

    replay: {
      async claim(namespace, value, ttl) {
        // Only a lapsed claim is cleared, so the insert below is what decides between racing claimers.
        await replay
          .createQueryBuilder()
          .delete()
          .where('namespace = :namespace and value = :value and expires_at <= :now', { namespace, value, now: now() })
          .execute()
        return insertIfAbsent(replay, { namespace, value, expires_at: now() + ttl * 1000 }, async () =>
          replay.existsBy({ namespace, value })
        )
      }
    },

    identities: {
      async find(provider: string, subject: string) {
        const row = await identities.findOneBy({ provider, subject })
        return row ? toIdentity(row) : undefined
      },
      async listForAccount(accountId: string) {
        return (await identities.findBy({ account_id: accountId })).map(toIdentity)
      },
      async upsert(identity: LinkedIdentity) {
        const row: IdentityRow = {
          provider: identity.provider,
          subject: identity.subject,
          account_id: identity.accountId,
          email: identity.email ?? null,
          claims: json(identity.claims),
          linked_at: identity.linkedAt.getTime()
        }
        await upsert(identities, row, ['provider', 'subject'])
      },
      async destroy(provider: string, subject: string) {
        await identities.delete({ provider, subject })
      }
    }
  }
}

export { POSTGRES_MIGRATIONS } from '../sql/postgres'
export { type Migration, SQLITE_MIGRATIONS } from '../sql/sqlite'
export * from './schema'
