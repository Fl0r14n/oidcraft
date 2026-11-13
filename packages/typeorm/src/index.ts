import type { AccountStore, Artifact, ArtifactKind, Credential, FullAdapter, KeyStore, LinkedIdentity, Realm } from '@oidcraft/adapter'
import { noAccounts } from '@oidcraft/adapter'
import type { ArtifactRow, ClientRow, CredentialRow, GrantRow, IdentityRow, RealmRow, ReplayRow, SessionRow } from '@oidcraft/sql/rows'
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
import { type DataSource, type FindOptionsWhere, IsNull, MoreThan, QueryFailedError, type Repository } from 'typeorm'
import { OIDCRAFT_TABLES } from './schema'

export type TypeormAdapterOptions = {
  /** Initialized, with `OIDCRAFT_SQLITE_ENTITIES` or `OIDCRAFT_POSTGRES_ENTITIES` among its entities and the migrations already run. */
  dataSource: DataSource
  keys: KeyStore
  /** Omitted, every account lookup misses: the host composes one in later, as `@oidcraft/provider/accounts` does. */
  accounts?: AccountStore
}

const now = () => Date.now()

// FR-A6: the DataSource is the host's, and its `invalidWhereValuesBehavior` can drop a missing value, so a lookup matches any row and a delete every one.
/** A bounded sweep in one statement: the key's rows among the first `limit` expired, still expired at the delete (NFR-P3). */
const pruneWhere = async (rows: Repository<any>, key: string[], before: Date, limit: number) => {
  const doomed = rows
    .createQueryBuilder('doomed')
    .select(key.map(column => `doomed.${column}`))
    .where('doomed.expires_at <= :before')
    .limit(limit)
  const result = await rows
    .createQueryBuilder()
    .delete()
    .where(`(${key.join(', ')}) in (${doomed.getQuery()})`)
    .andWhere('expires_at <= :before')
    .setParameters({ before: before.getTime() })
    .execute()
  return result.affected ?? 0
}

const by = <T extends object>(where: T) => {
  for (const [column, value] of Object.entries(where)) {
    if (value === undefined || value === null) throw new TypeError(`the ${column} to look up by is ${value}`)
  }
  return where
}

// FR-T5: a grant may carry an expiry, which the query enforces as it does an artifact's.
const grantLive = (where: FindOptionsWhere<GrantRow>) => [
  { ...by(where), expires_at: IsNull() },
  { ...where, expires_at: MoreThan(now()) }
]

const upsert = async <T extends object>(
  repository: Repository<T>,
  row: T,
  conflict: (keyof T & string)[],
  overwrite?: (keyof T & string)[]
) => {
  const columns = overwrite ?? (Object.keys(row) as (keyof T & string)[]).filter(column => !conflict.includes(column))
  await repository.createQueryBuilder().insert().values(row).orUpdate(columns, conflict).execute()
}

/** `orIgnore` hides whether it wrote, so a failed insert is a lost race only if `collided` finds the row; else rethrown (FR-A3, NFR-S4). */
const insertIfAbsent = async <T extends object>(repository: Repository<T>, row: T, collided: () => Promise<boolean>) => {
  try {
    await repository.insert(row as never)
    return true
  } catch (error) {
    if (error instanceof QueryFailedError && (await collided())) return false
    throw error
  }
}

/** The Drizzle and Kysely adapters' contract on the host's TypeORM `DataSource` (FR-A6). */
export const typeormAdapter = (options: TypeormAdapterOptions): FullAdapter => {
  const { dataSource } = options
  const missing = OIDCRAFT_TABLES.filter(table => !dataSource.hasMetadata(table))
  if (missing.length) {
    throw new Error(
      `the DataSource does not know ${missing.join(', ')}: add OIDCRAFT_SQLITE_ENTITIES or OIDCRAFT_POSTGRES_ENTITIES to its entities`
    )
  }
  const clients = dataSource.getRepository<ClientRow>('oidc_clients')
  const artifactRows = dataSource.getRepository<ArtifactRow>('oidc_artifacts')
  const sessions = dataSource.getRepository<SessionRow>('oidc_sessions')
  const grants = dataSource.getRepository<GrantRow>('oidc_grants')
  const identities = dataSource.getRepository<IdentityRow>('oidc_identities')
  const replay = dataSource.getRepository<ReplayRow>('oidc_replay')
  const credentials = dataSource.getRepository<CredentialRow>('oidc_credentials')
  const realms = dataSource.getRepository<RealmRow>('oidc_realms')

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
      await artifactRows.delete(by({ kind, id }))
    },

    async revokeByGrantId(grantId: string) {
      // One indexed delete, not a scan (FR-A5).
      await artifactRows.delete(by({ grant_id: grantId }))
    },

    async revokeByFamilyId(familyId: string) {
      await artifactRows.delete(by({ family_id: familyId }))
    },

    async revokeByClientId(clientId: string) {
      await artifactRows.delete(by({ client_id: clientId }))
    },

    async prune(before: Date, limit: number) {
      // One bounded statement, expired still at the delete: a row rewritten since the select is live again (NFR-P3).
      return pruneWhere(artifactRows, ['kind', 'id'], before, limit)
    }
  }

  return {
    clients: {
      async find(clientId) {
        const row = await clients.findOneBy(by({ client_id: clientId }))
        if (!row) return undefined
        return toClient(row)
      },
      async upsert(client) {
        await upsert(clients, clientRow(client), ['client_id'], ['data', 'updated_at'])
      },
      async destroy(clientId) {
        await clients.delete(by({ client_id: clientId }))
      },
      async list(cursor, limit) {
        const query = clients.createQueryBuilder('c').orderBy('c.client_id')
        if (cursor !== undefined) query.where('c.client_id > :cursor', { cursor })
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
      // Compare-and-swap, retried while another writer wins, so concurrent sign-ins are all recorded (FR-C11).
      async addClient(id, clientId) {
        for (let attempt = 0; attempt < 64; attempt++) {
          const row = await sessions.findOne({ where: by({ id }), select: { clients: true } })
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
        await sessions.delete(by({ id }))
      },
      async prune(before, limit) {
        return pruneWhere(sessions, ['id'], before, limit)
      }
    },

    grants: {
      async find(id) {
        const row = await grants.findOneBy(grantLive({ id }))
        return row ? toGrant(row) : undefined
      },
      async findByAccountAndClient(accountId, clientId) {
        const row = await grants.findOneBy(grantLive({ account_id: accountId, client_id: clientId }))
        return row ? toGrant(row) : undefined
      },
      async listForAccount(accountId) {
        return (await grants.findBy(grantLive({ account_id: accountId }))).map(toGrant)
      },
      async upsert(grant) {
        await upsert(grants, grantRow(grant), ['account_id', 'client_id'], ['scopes', 'claims', 'resources', 'expires_at'])
      },
      async destroy(id) {
        await grants.delete(by({ id }))
      },
      async destroyByClientId(clientId) {
        await grants.delete(by({ client_id: clientId }))
      }
    },

    accounts: options.accounts ?? noAccounts,

    credentials: {
      async find(accountId: string) {
        const row = await credentials.findOneBy(by({ account_id: accountId }))
        return row ? toCredential(row) : undefined
      },
      async findByUsername(username: string) {
        const row = await credentials.findOneBy(by({ username }))
        return row ? toCredential(row) : undefined
      },
      // Both the key and the username are unique; a collision on either is a lost race.
      async create(credential: Credential) {
        return insertIfAbsent(credentials, credentialRow(credential), async () =>
          credentials.exists({ where: [by({ account_id: credential.accountId }), by({ username: credential.username })] })
        )
      },
      async upsert(credential: Credential) {
        await upsert(credentials, credentialRow(credential), ['account_id'])
      },
      async destroy(accountId: string) {
        await credentials.delete(by({ account_id: accountId }))
      }
    },

    realms: {
      async find(id: string) {
        const row = await realms.findOneBy(by({ id }))
        return row ? toRealm(row) : undefined
      },
      async list() {
        return (await realms.find()).map(toRealm)
      },
      async create(realm: Realm) {
        return insertIfAbsent(realms, realmRow(realm), async () => realms.existsBy(by({ id: realm.id })))
      },
      async upsert(realm: Realm) {
        await upsert(realms, realmRow(realm), ['id'])
      },
      async destroy(id: string) {
        await realms.delete(by({ id }))
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
          replay.existsBy(by({ namespace, value }))
        )
      },
      async prune(before, limit) {
        return pruneWhere(replay, ['namespace', 'value'], before, limit)
      }
    },

    identities: {
      async find(provider: string, subject: string) {
        const row = await identities.findOneBy(by({ provider, subject }))
        return row ? toIdentity(row) : undefined
      },
      async listForAccount(accountId: string) {
        return (await identities.findBy(by({ account_id: accountId }))).map(toIdentity)
      },
      async upsert(identity: LinkedIdentity) {
        await upsert(identities, identityRow(identity), ['provider', 'subject'])
      },
      async destroy(provider: string, subject: string) {
        await identities.delete(by({ provider, subject }))
      }
    }
  }
}

export { POSTGRES_MIGRATIONS } from '@oidcraft/sql/postgres'
export { type Migration, SQLITE_MIGRATIONS } from '@oidcraft/sql/sqlite'
export * from './schema'
