import type {
  AccountStore,
  Artifact,
  ArtifactKind,
  Credential,
  FullAdapter,
  KeyStore,
  LinkedIdentity,
  Passkey,
  Realm
} from '@oidcraft/adapter'
import { grantExpired, MERGE_ROUNDS, mergedGrant, noAccounts } from '@oidcraft/adapter'
import {
  artifactRow,
  clientRow,
  credentialRow,
  grantRow,
  identityRow,
  json,
  passkeyRow,
  realmRow,
  replayDigest,
  sessionRow,
  toArtifact,
  toClient,
  toCredential,
  toGrant,
  toIdentity,
  toPasskey,
  toRealm,
  toSession
} from '@oidcraft/sql/rows'
import { type ExpressionBuilder, type InsertQueryBuilder, type InsertResult, type Kysely, MysqlAdapter, type UpdateObject } from 'kysely'
import type { OidcraftDatabase } from './schema'

export type KyselyAdapterOptions = {
  /** On SQLite, Postgres, or MySQL and MariaDB through `MysqlDialect`, each over its own migrations (FR-A4). */
  db: Kysely<OidcraftDatabase>
  keys: KeyStore
  /** Omitted, every account lookup misses: the host composes one in later, as `@oidcraft/provider/accounts` does. */
  accounts?: AccountStore
}

const now = () => Date.now()

// FR-T5: a grant may carry an expiry, which the query enforces as it does an artifact's.
const grantLive = (eb: ExpressionBuilder<OidcraftDatabase, 'oidc_grants'>) =>
  eb.or([eb('expires_at', 'is', null), eb('expires_at', '>', now())])

type Table = keyof OidcraftDatabase

/** ER_DUP_ENTRY, the same on MySQL and MariaDB. */
const duplicateKey = (error: unknown) => (error as { errno?: unknown } | undefined)?.errno === 1062

/** The Drizzle adapter's contract on a query builder; both pass the one conformance suite (FR-A4). */
export const kyselyAdapter = (options: KyselyAdapterOptions): FullAdapter => {
  const { db } = options
  // MySQL and MariaDB share neither `RETURNING` nor `ON CONFLICT`, and a host's connection may count matched rows as
  // affected (CLIENT_FOUND_ROWS, mysql2's default): so no count read here depends on which.
  const mysql = db.getExecutor().adapter instanceof MysqlAdapter

  /** Atomic: true for exactly one of racing writers (FR-A3). */
  const insertIfAbsent = async <TB extends Table>(insert: InsertQueryBuilder<OidcraftDatabase, TB, InsertResult>) => {
    if (!mysql) return Number((await insert.onConflict(conflict => conflict.doNothing()).executeTakeFirst()).numInsertedOrUpdatedRows) === 1
    try {
      await insert.execute()
      return true
    } catch (error) {
      if (duplicateKey(error)) return false
      throw error
    }
  }

  /** On MySQL a clash on any unique key updates, so only a table whose one unique key is `conflict` may use this. */
  const upsert = async <TB extends Table>(
    insert: InsertQueryBuilder<OidcraftDatabase, TB, InsertResult>,
    conflict: (keyof OidcraftDatabase[TB] & string)[],
    set: UpdateObject<OidcraftDatabase, TB, TB>
  ) => {
    await (mysql
      ? insert.onDuplicateKeyUpdate(set)
      : insert.onConflict(builder => builder.columns(conflict as never).doUpdateSet(set as never))
    ).execute()
  }

  /** MySQL refuses a `LIMIT` in an `IN` subquery on the table being deleted from, and has `DELETE … LIMIT` instead. */
  const pruneMysql = async (table: 'oidc_artifacts' | 'oidc_sessions' | 'oidc_replay', at: number, limit: number) => {
    const { numDeletedRows } = await db
      .deleteFrom(table)
      .where('expires_at', '<=', at)
      .orderBy('expires_at')
      .limit(limit)
      .executeTakeFirstOrThrow()
    return Number(numDeletedRows)
  }

  const artifacts = {
    async upsert(artifact: Artifact) {
      const row = artifactRow(artifact)
      await upsert(db.insertInto('oidc_artifacts').values(row), ['kind', 'id'], { ...row, consumed_at: undefined })
    },

    async find(kind: ArtifactKind, id: string) {
      const row = await db
        .selectFrom('oidc_artifacts')
        .selectAll()
        .where('kind', '=', kind)
        .where('id', '=', id)
        // FR-T5: enforced by the query, so a missed prune still cannot serve an expired token.
        .where('expires_at', '>', now())
        .executeTakeFirst()
      return row ? toArtifact(row) : undefined
    },

    async findByUserCode(userCode: string) {
      const row = await db
        .selectFrom('oidc_artifacts')
        .selectAll()
        .where('user_code', '=', userCode)
        .where('expires_at', '>', now())
        .executeTakeFirst()
      return row ? toArtifact(row) : undefined
    },

    async consume(kind: ArtifactKind, id: string) {
      const result = await db
        .updateTable('oidc_artifacts')
        .set({ consumed_at: now() })
        .where('kind', '=', kind)
        .where('id', '=', id)
        .where('consumed_at', 'is', null)
        .where('expires_at', '>', now())
        .executeTakeFirst()
      return Number(result.numUpdatedRows) === 1
    },

    async destroy(kind: ArtifactKind, id: string) {
      await db.deleteFrom('oidc_artifacts').where('kind', '=', kind).where('id', '=', id).execute()
    },

    async revokeByGrantId(grantId: string) {
      // One indexed delete, not a scan (FR-A5).
      await db.deleteFrom('oidc_artifacts').where('grant_id', '=', grantId).execute()
    },

    async revokeByFamilyId(familyId: string) {
      await db.deleteFrom('oidc_artifacts').where('family_id', '=', familyId).execute()
    },

    async revokeByClientId(clientId: string) {
      await db.deleteFrom('oidc_artifacts').where('client_id', '=', clientId).execute()
    },

    async prune(before: Date, limit: number) {
      const at = before.getTime()
      if (mysql) return pruneMysql('oidc_artifacts', at, limit)
      // One bounded statement, expired still at the delete: a row rewritten since the select is live again (NFR-P3).
      const { numDeletedRows } = await db
        .deleteFrom('oidc_artifacts')
        .where(eb =>
          eb(
            eb.refTuple('kind', 'id'),
            'in',
            eb.selectFrom('oidc_artifacts').select(['kind', 'id']).where('expires_at', '<=', at).limit(limit).$asTuple('kind', 'id')
          )
        )
        .where('expires_at', '<=', at)
        .executeTakeFirstOrThrow()
      return Number(numDeletedRows)
    }
  }

  const sessions = {
    async prune(before: Date, limit: number) {
      const at = before.getTime()
      if (mysql) return pruneMysql('oidc_sessions', at, limit)
      const { numDeletedRows } = await db
        .deleteFrom('oidc_sessions')
        .where('id', 'in', eb => eb.selectFrom('oidc_sessions').select('id').where('expires_at', '<=', at).limit(limit))
        .where('expires_at', '<=', at)
        .executeTakeFirstOrThrow()
      return Number(numDeletedRows)
    }
  }

  const replay = {
    async prune(before: Date, limit: number) {
      const at = before.getTime()
      if (mysql) return pruneMysql('oidc_replay', at, limit)
      const { numDeletedRows } = await db
        .deleteFrom('oidc_replay')
        .where(eb =>
          eb(
            eb.refTuple('namespace', 'value'),
            'in',
            eb
              .selectFrom('oidc_replay')
              .select(['namespace', 'value'])
              .where('expires_at', '<=', at)
              .limit(limit)
              .$asTuple('namespace', 'value')
          )
        )
        .where('expires_at', '<=', at)
        .executeTakeFirstOrThrow()
      return Number(numDeletedRows)
    }
  }

  return {
    clients: {
      async find(clientId) {
        const row = await db.selectFrom('oidc_clients').selectAll().where('client_id', '=', clientId).executeTakeFirst()
        if (!row) return undefined
        return toClient(row)
      },
      async upsert(client) {
        const row = clientRow(client)
        const { data, updated_at } = row
        await upsert(db.insertInto('oidc_clients').values(row), ['client_id'], { data, updated_at })
      },
      async destroy(clientId) {
        await db.deleteFrom('oidc_clients').where('client_id', '=', clientId).execute()
      },
      async list(cursor, limit) {
        let query = db.selectFrom('oidc_clients').selectAll().orderBy('client_id')
        if (cursor !== undefined) query = query.where('client_id', '>', cursor)
        const rows = await (limit === undefined ? query : query.limit(limit + 1)).execute()
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
        const row = await db.selectFrom('oidc_sessions').selectAll().where('id', '=', id).where('expires_at', '>', now()).executeTakeFirst()
        return row ? toSession(row) : undefined
      },
      async listForAccount(accountId) {
        const rows = await db
          .selectFrom('oidc_sessions')
          .selectAll()
          .where('account_id', '=', accountId)
          .where('expires_at', '>', now())
          .execute()
        return rows.map(toSession)
      },
      async findByUpstreamSession(provider, upstreamSessionId) {
        const rows = await db
          .selectFrom('oidc_sessions')
          .selectAll()
          .where('idp', '=', provider)
          .where('upstream_session_id', '=', upstreamSessionId)
          .where('expires_at', '>', now())
          .execute()
        return rows.map(toSession)
      },
      async upsert(session) {
        const row = sessionRow(session)
        await upsert(db.insertInto('oidc_sessions').values(row), ['id'], row)
      },
      // Compare-and-swap, retried while another writer wins, so concurrent sign-ins are all recorded (FR-C11).
      async addClient(id, clientId) {
        for (let attempt = 0; attempt < 64; attempt++) {
          const row = await db.selectFrom('oidc_sessions').select('clients').where('id', '=', id).executeTakeFirst()
          if (!row) return
          const current = JSON.parse(row.clients) as string[]
          if (current.includes(clientId)) return
          const result = await db
            .updateTable('oidc_sessions')
            .set({ clients: json([...current, clientId]) })
            .where('id', '=', id)
            .where('clients', '=', row.clients)
            .executeTakeFirst()
          if (Number(result.numUpdatedRows) > 0) return
        }
        throw new Error(`session ${id} kept changing; its client list could not be updated`)
      },
      async destroy(id) {
        await db.deleteFrom('oidc_sessions').where('id', '=', id).execute()
      },
      prune: sessions.prune
    },

    grants: {
      async find(id) {
        const row = await db.selectFrom('oidc_grants').selectAll().where('id', '=', id).where(grantLive).executeTakeFirst()
        return row ? toGrant(row) : undefined
      },
      async findByAccountAndClient(accountId, clientId) {
        const row = await db
          .selectFrom('oidc_grants')
          .selectAll()
          .where('account_id', '=', accountId)
          .where('client_id', '=', clientId)
          .where(grantLive)
          .executeTakeFirst()
        return row ? toGrant(row) : undefined
      },
      async listForAccount(accountId) {
        return (await db.selectFrom('oidc_grants').selectAll().where('account_id', '=', accountId).where(grantLive).execute()).map(toGrant)
      },
      async upsert(grant) {
        const row = grantRow(grant)
        await upsert(db.insertInto('oidc_grants').values(row), ['account_id', 'client_id'], {
          scopes: row.scopes,
          claims: row.claims,
          resources: row.resources,
          expires_at: row.expires_at
        })
      },
      // FR-I4: compare-and-swap on the stored text, so a consent landing between the read and the write is never overwritten.
      async merge(grant) {
        for (let round = 0; round < MERGE_ROUNDS; round++) {
          const row = await db
            .selectFrom('oidc_grants')
            .selectAll()
            .where('account_id', '=', grant.accountId)
            .where('client_id', '=', grant.clientId)
            .executeTakeFirst()
          if (!row) {
            if (await insertIfAbsent(db.insertInto('oidc_grants').values(grantRow(grant)))) return grant
            continue
          }
          const held = toGrant(row)
          if (grantExpired(held)) {
            await db.deleteFrom('oidc_grants').where('id', '=', held.id).where('expires_at', '<=', Date.now()).execute()
            continue
          }
          const merged = grantRow(mergedGrant(held, grant))
          // Nothing new: an update that changes nothing counts no row without CLIENT_FOUND_ROWS, and would look like a lost race.
          if (merged.scopes === row.scopes && merged.claims === row.claims && merged.resources === row.resources) return held
          const swapped = await db
            .updateTable('oidc_grants')
            .set({ scopes: merged.scopes, claims: merged.claims, resources: merged.resources })
            .where('id', '=', row.id)
            .where('scopes', '=', row.scopes)
            .where('claims', '=', row.claims)
            .where('resources', '=', row.resources)
            .executeTakeFirst()
          if (Number(swapped.numUpdatedRows) === 1) return mergedGrant(held, grant)
        }
        throw new Error(`the grant for ${grant.accountId} and ${grant.clientId} kept changing under the merge`)
      },
      async destroy(id) {
        await db.deleteFrom('oidc_grants').where('id', '=', id).execute()
      },
      async destroyByClientId(clientId) {
        await db.deleteFrom('oidc_grants').where('client_id', '=', clientId).execute()
      }
    },

    accounts: options.accounts ?? noAccounts,

    credentials: {
      async find(accountId: string) {
        const row = await db.selectFrom('oidc_credentials').selectAll().where('account_id', '=', accountId).executeTakeFirst()
        return row ? toCredential(row) : undefined
      },
      async findByUsername(username: string) {
        const row = await db.selectFrom('oidc_credentials').selectAll().where('username', '=', username).executeTakeFirst()
        return row ? toCredential(row) : undefined
      },
      // Both the key and the username are unique, and DO NOTHING without a target covers either.
      async create(credential: Credential) {
        return insertIfAbsent(db.insertInto('oidc_credentials').values(credentialRow(credential)))
      },
      async upsert(credential: Credential) {
        const row = credentialRow(credential)
        if (!mysql) {
          await upsert(db.insertInto('oidc_credentials').values(row), ['account_id'], row)
          return
        }
        // ON DUPLICATE KEY UPDATE answers a clash on the username too, by rewriting the other account's row; this throws.
        const held = await db
          .selectFrom('oidc_credentials')
          .select('account_id')
          .where('account_id', '=', row.account_id)
          .executeTakeFirst()
        if (!held) {
          await db.insertInto('oidc_credentials').values(row).execute()
          return
        }
        const { account_id, ...rest } = row
        await db.updateTable('oidc_credentials').set(rest).where('account_id', '=', account_id).execute()
      },
      async destroy(accountId: string) {
        await db.deleteFrom('oidc_credentials').where('account_id', '=', accountId).execute()
      }
    },

    passkeys: {
      async find(credentialId: string) {
        const row = await db.selectFrom('oidc_passkeys').selectAll().where('credential_id', '=', credentialId).executeTakeFirst()
        return row ? toPasskey(row) : undefined
      },
      async listForAccount(accountId: string) {
        return (await db.selectFrom('oidc_passkeys').selectAll().where('account_id', '=', accountId).execute()).map(toPasskey)
      },
      async create(passkey: Passkey) {
        return insertIfAbsent(db.insertInto('oidc_passkeys').values(passkeyRow(passkey)))
      },
      async upsert(passkey: Passkey) {
        const row = passkeyRow(passkey)
        await upsert(db.insertInto('oidc_passkeys').values(row), ['credential_id'], row)
      },
      async destroy(credentialId: string) {
        await db.deleteFrom('oidc_passkeys').where('credential_id', '=', credentialId).execute()
      }
    },

    realms: {
      async find(id: string) {
        const row = await db.selectFrom('oidc_realms').selectAll().where('id', '=', id).executeTakeFirst()
        return row ? toRealm(row) : undefined
      },
      async list() {
        return (await db.selectFrom('oidc_realms').selectAll().execute()).map(toRealm)
      },
      async create(realm: Realm) {
        return insertIfAbsent(db.insertInto('oidc_realms').values(realmRow(realm)))
      },
      async upsert(realm: Realm) {
        const row = realmRow(realm)
        await upsert(db.insertInto('oidc_realms').values(row), ['id'], row)
      },
      async destroy(id: string) {
        await db.deleteFrom('oidc_realms').where('id', '=', id).execute()
      }
    },
    keys: options.keys,

    replay: {
      async claim(namespace, value, ttl) {
        const expires_at = now() + ttl * 1000
        if (mysql) {
          const key = await replayDigest(value)
          // Only a lapsed claim is cleared, so the insert is what decides between racing claimers.
          await db
            .deleteFrom('oidc_replay')
            .where('namespace', '=', namespace)
            .where('value', '=', key)
            .where('expires_at', '<=', now())
            .execute()
          return insertIfAbsent(db.insertInto('oidc_replay').values({ namespace, value: key, expires_at }))
        }
        // One statement: a fresh row is inserted, a lapsed one is taken over, a live one is left alone.
        const result = await db
          .insertInto('oidc_replay')
          .values({ namespace, value, expires_at })
          .onConflict(conflict =>
            conflict.columns(['namespace', 'value']).doUpdateSet({ expires_at }).where('oidc_replay.expires_at', '<=', now())
          )
          .returning('value')
          .executeTakeFirst()
        return result !== undefined
      },
      prune: replay.prune
    },

    identities: {
      async find(provider: string, subject: string) {
        const row = await db
          .selectFrom('oidc_identities')
          .selectAll()
          .where('provider', '=', provider)
          .where('subject', '=', subject)
          .executeTakeFirst()
        return row ? toIdentity(row) : undefined
      },
      async listForAccount(accountId: string) {
        return (await db.selectFrom('oidc_identities').selectAll().where('account_id', '=', accountId).execute()).map(toIdentity)
      },
      async upsert(identity: LinkedIdentity) {
        const row = identityRow(identity)
        await upsert(db.insertInto('oidc_identities').values(row), ['provider', 'subject'], row)
      },
      async destroy(provider: string, subject: string) {
        await db.deleteFrom('oidc_identities').where('provider', '=', provider).where('subject', '=', subject).execute()
      }
    }
  }
}

export { MYSQL_MIGRATIONS } from '@oidcraft/sql/mysql'
export { POSTGRES_MIGRATIONS } from '@oidcraft/sql/postgres'
export { type Migration, SQLITE_MIGRATIONS } from '@oidcraft/sql/sqlite'
export type { OidcraftDatabase } from './schema'
export * from './schema'
