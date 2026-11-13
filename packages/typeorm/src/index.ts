import type { AccountStore, Artifact, ArtifactKind, Credential, FullAdapter, KeyStore, LinkedIdentity, Realm } from '@oidcraft/adapter'
import { noAccounts } from '@oidcraft/adapter'
import {
  artifactRow,
  clientRow,
  credentialRow,
  grantRow,
  identityRow,
  json,
  parse,
  realmRow,
  sessionRow,
  toArtifact,
  toClient,
  toCredential,
  toGrant,
  toIdentity,
  toRealm,
  toSession
} from '@oidcraft/sql/rows'
import { type DataSource, type EntitySchema, QueryFailedError, type Repository } from 'typeorm'
import {
  ArtifactEntity,
  ClientEntity,
  CredentialEntity,
  GrantEntity,
  IdentityEntity,
  OIDCRAFT_ENTITIES,
  RealmEntity,
  ReplayEntity,
  SessionEntity
} from './schema'

export type TypeormAdapterOptions = {
  /** Initialized, with `OIDCRAFT_ENTITIES` among its entities and the migrations already run. */
  dataSource: DataSource
  keys: KeyStore
  /** Omitted, every account lookup misses: the host composes one in later, as `@oidcraft/provider/accounts` does. */
  accounts?: AccountStore
}

const now = () => Date.now()

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
      const row = artifactRow(artifact)
      // consumed_at is left out of the update: an upsert must never revive a consumed artifact.
      await upsert(
        artifactRows,
        row,
        ['kind', 'id'],
        ['client_id', 'account_id', 'grant_id', 'family_id', 'user_code', 'payload', 'expires_at']
      )
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

    async revokeByFamilyId(familyId: string) {
      await artifactRows.delete({ family_id: familyId })
    },

    async revokeByClientId(clientId: string) {
      await artifactRows.delete({ client_id: clientId })
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
        return toClient(row)
      },
      async upsert(client) {
        await upsert(clients, clientRow(client), ['client_id'], ['data', 'updated_at'])
      },
      async destroy(clientId) {
        await clients.delete({ client_id: clientId })
      },
      async list(cursor, limit) {
        const query = clients.createQueryBuilder('c').orderBy('c.client_id')
        if (cursor !== undefined) query.where('c.client_id > :cursor', { cursor })
        // One more than asked, to know whether another page follows.
        if (limit !== undefined) query.limit(limit + 1)
        const rows = await query.getMany()
        const more = limit !== undefined && rows.length > limit
        const shown = more ? rows.slice(0, limit) : rows
        return {
          clients: shown.map(toClient),
          ...(more && { cursor: shown.at(-1)?.client_id as string })
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
        const rows = await sessions
          .createQueryBuilder('s')
          .where('s.idp = :provider and s.upstream_session_id = :upstreamSessionId and s.expires_at > :now', {
            provider,
            upstreamSessionId,
            now: now()
          })
          .getMany()
        return rows.map(toSession)
      },
      async upsert(session) {
        await upsert(sessions, sessionRow(session), ['id'])
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
      },
      async prune(before, limit) {
        const doomed = await sessions
          .createQueryBuilder('s')
          .select(['s.id'])
          .where('s.expires_at <= :before', { before: before.getTime() })
          .limit(limit)
          .getMany()
        for (const row of doomed) {
          await sessions
            .createQueryBuilder()
            .delete()
            .where('id = :id and expires_at <= :before', { id: row.id, before: before.getTime() })
            .execute()
        }
        return doomed.length
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
        await upsert(grants, grantRow(grant), ['account_id', 'client_id'], ['scopes', 'claims', 'resources', 'expires_at'])
      },
      async destroy(id) {
        await grants.delete({ id })
      },
      async destroyByClientId(clientId) {
        await grants.delete({ client_id: clientId })
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
      },
      async prune(before, limit) {
        const doomed = await replay
          .createQueryBuilder('r')
          .select(['r.namespace', 'r.value'])
          .where('r.expires_at <= :before', { before: before.getTime() })
          .limit(limit)
          .getMany()
        for (const row of doomed) {
          await replay
            .createQueryBuilder()
            .delete()
            .where('namespace = :namespace and value = :value and expires_at <= :before', { ...row, before: before.getTime() })
            .execute()
        }
        return doomed.length
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
        await upsert(identities, identityRow(identity), ['provider', 'subject'])
      },
      async destroy(provider: string, subject: string) {
        await identities.delete({ provider, subject })
      }
    }
  }
}

export { POSTGRES_MIGRATIONS } from '@oidcraft/sql/postgres'
export { type Migration, SQLITE_MIGRATIONS } from '@oidcraft/sql/sqlite'
export * from './schema'
