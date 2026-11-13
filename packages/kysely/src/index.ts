import type { AccountStore, Artifact, ArtifactKind, Credential, FullAdapter, KeyStore, LinkedIdentity, Realm } from '@oidcraft/adapter'
import { noAccounts } from '@oidcraft/adapter'
import {
  artifactRow,
  clientRow,
  credentialRow,
  grantRow,
  identityRow,
  json,
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
import type { Kysely } from 'kysely'
import type { OidcraftDatabase } from './schema'

export type KyselyAdapterOptions = {
  db: Kysely<OidcraftDatabase>
  keys: KeyStore
  /** Omitted, every account lookup misses: the host composes one in later, as `@oidcraft/provider/accounts` does. */
  accounts?: AccountStore
}

const now = () => Date.now()

/** The Drizzle adapter's contract on a query builder; both pass the one conformance suite (FR-A4). */
export const kyselyAdapter = (options: KyselyAdapterOptions): FullAdapter => {
  const { db } = options

  const artifacts = {
    async upsert(artifact: Artifact) {
      const row = artifactRow(artifact)
      await db
        .insertInto('oidc_artifacts')
        .values(row)
        .onConflict(conflict => conflict.columns(['kind', 'id']).doUpdateSet({ ...row, consumed_at: undefined }))
        .execute()
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
        .returning('id')
        .executeTakeFirst()
      return result !== undefined
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
      const doomed = await db
        .selectFrom('oidc_artifacts')
        .select(['kind', 'id'])
        .where('expires_at', '<=', before.getTime())
        .limit(limit)
        .execute()
      for (const row of doomed) await artifacts.destroy(row.kind as ArtifactKind, row.id)
      return doomed.length
    }
  }

  const sessions = {
    async prune(before: Date, limit: number) {
      const doomed = await db.selectFrom('oidc_sessions').select('id').where('expires_at', '<=', before.getTime()).limit(limit).execute()
      if (doomed.length) {
        await db
          .deleteFrom('oidc_sessions')
          .where(
            'id',
            'in',
            doomed.map(row => row.id)
          )
          .where('expires_at', '<=', before.getTime())
          .execute()
      }
      return doomed.length
    }
  }

  const replay = {
    async prune(before: Date, limit: number) {
      const doomed = await db
        .selectFrom('oidc_replay')
        .select(['namespace', 'value'])
        .where('expires_at', '<=', before.getTime())
        .limit(limit)
        .execute()
      for (const row of doomed) {
        await db
          .deleteFrom('oidc_replay')
          .where('namespace', '=', row.namespace)
          .where('value', '=', row.value)
          .where('expires_at', '<=', before.getTime())
          .execute()
      }
      return doomed.length
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
        await db
          .insertInto('oidc_clients')
          .values(row)
          .onConflict(conflict => conflict.column('client_id').doUpdateSet({ data, updated_at }))
          .execute()
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
        await db
          .insertInto('oidc_sessions')
          .values(row)
          .onConflict(conflict => conflict.column('id').doUpdateSet(row))
          .execute()
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
        const row = await db.selectFrom('oidc_grants').selectAll().where('id', '=', id).executeTakeFirst()
        return row ? toGrant(row) : undefined
      },
      async findByAccountAndClient(accountId, clientId) {
        const row = await db
          .selectFrom('oidc_grants')
          .selectAll()
          .where('account_id', '=', accountId)
          .where('client_id', '=', clientId)
          .executeTakeFirst()
        return row ? toGrant(row) : undefined
      },
      async listForAccount(accountId) {
        return (await db.selectFrom('oidc_grants').selectAll().where('account_id', '=', accountId).execute()).map(toGrant)
      },
      async upsert(grant) {
        const row = grantRow(grant)
        await db
          .insertInto('oidc_grants')
          .values(row)
          .onConflict(conflict =>
            conflict
              .columns(['account_id', 'client_id'])
              .doUpdateSet({ scopes: row.scopes, claims: row.claims, resources: row.resources, expires_at: row.expires_at })
          )
          .execute()
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
        const won = await db
          .insertInto('oidc_credentials')
          .values(credentialRow(credential))
          .onConflict(conflict => conflict.doNothing())
          .returning('account_id')
          .executeTakeFirst()
        return won !== undefined
      },
      async upsert(credential: Credential) {
        const row = credentialRow(credential)
        await db
          .insertInto('oidc_credentials')
          .values(row)
          .onConflict(conflict => conflict.column('account_id').doUpdateSet(row))
          .execute()
      },
      async destroy(accountId: string) {
        await db.deleteFrom('oidc_credentials').where('account_id', '=', accountId).execute()
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
        const won = await db
          .insertInto('oidc_realms')
          .values(realmRow(realm))
          .onConflict(conflict => conflict.doNothing())
          .returning('id')
          .executeTakeFirst()
        return won !== undefined
      },
      async upsert(realm: Realm) {
        const row = realmRow(realm)
        await db
          .insertInto('oidc_realms')
          .values(row)
          .onConflict(conflict => conflict.column('id').doUpdateSet(row))
          .execute()
      },
      async destroy(id: string) {
        await db.deleteFrom('oidc_realms').where('id', '=', id).execute()
      }
    },
    keys: options.keys,

    replay: {
      async claim(namespace, value, ttl) {
        const expires_at = now() + ttl * 1000
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
        await db
          .insertInto('oidc_identities')
          .values(row)
          .onConflict(conflict => conflict.columns(['provider', 'subject']).doUpdateSet(row))
          .execute()
      },
      async destroy(provider: string, subject: string) {
        await db.deleteFrom('oidc_identities').where('provider', '=', provider).where('subject', '=', subject).execute()
      }
    }
  }
}

export { POSTGRES_MIGRATIONS } from '@oidcraft/sql/postgres'
export { type Migration, SQLITE_MIGRATIONS } from '@oidcraft/sql/sqlite'
export type { OidcraftDatabase } from './schema'
export * from './schema'
