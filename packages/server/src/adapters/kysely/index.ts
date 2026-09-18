import type { Kysely, Selectable } from 'kysely'
import type { AccountStore, Adapter, Artifact, ArtifactKind, Client, FederatedIdentity, Grant, KeyStore, Session } from 'oidcraft'
import type { ArtifactsTable, GrantsTable, IdentitiesTable, OidcraftDatabase, SessionsTable } from './schema'

export type KyselyAdapterOptions = {
  db: Kysely<OidcraftDatabase>
  keys: KeyStore
  accounts: AccountStore
  federation?: boolean
}

const now = () => Date.now()
const json = (value: unknown) => JSON.stringify(value)
const parse = <T>(value: string) => JSON.parse(value) as T

const toArtifact = (row: Selectable<ArtifactsTable>): Artifact => ({
  id: row.id,
  kind: row.kind as ArtifactKind,
  clientId: row.client_id,
  ...(row.account_id && { accountId: row.account_id }),
  ...(row.grant_id && { grantId: row.grant_id }),
  payload: parse<Record<string, unknown>>(row.payload),
  ...(row.consumed_at && { consumedAt: new Date(row.consumed_at) }),
  expiresAt: new Date(row.expires_at)
})

const toSession = (row: Selectable<SessionsTable>): Session => ({
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

const toGrant = (row: Selectable<GrantsTable>): Grant => ({
  id: row.id,
  accountId: row.account_id,
  clientId: row.client_id,
  scopes: parse<string[]>(row.scopes),
  claims: parse<string[]>(row.claims),
  resources: parse<Record<string, string[]>>(row.resources),
  createdAt: new Date(row.created_at),
  ...(row.expires_at && { expiresAt: new Date(row.expires_at) })
})

const toIdentity = (row: Selectable<IdentitiesTable>): FederatedIdentity => ({
  accountId: row.account_id,
  provider: row.provider,
  subject: row.subject,
  ...(row.email && { email: row.email }),
  claims: parse<Record<string, unknown>>(row.claims),
  linkedAt: new Date(row.linked_at)
})

/**
 * The same contract as the Drizzle adapter, on a query builder rather than an ORM (FR-A4). Both run
 * the one conformance suite, which is what makes "interchangeable" checkable rather than asserted.
 */
export const kyselyAdapter = (options: KyselyAdapterOptions): Adapter => {
  const { db } = options
  const federation = options.federation !== false

  const artifacts = {
    async upsert(artifact: Artifact) {
      const row = {
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
      await db
        .insertInto('oidc_artifacts')
        .values(row)
        .onConflict(conflict => conflict.columns(['kind', 'id']).doUpdateSet(row))
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
      await db.updateTable('oidc_artifacts').set({ consumed_at: now() }).where('kind', '=', kind).where('id', '=', id).execute()
    },

    async destroy(kind: ArtifactKind, id: string) {
      await db.deleteFrom('oidc_artifacts').where('kind', '=', kind).where('id', '=', id).execute()
    },

    async revokeByGrantId(grantId: string) {
      // One indexed delete, not a scan (FR-A5).
      await db.deleteFrom('oidc_artifacts').where('grant_id', '=', grantId).execute()
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

  return {
    clients: {
      async find(clientId) {
        const row = await db.selectFrom('oidc_clients').selectAll().where('client_id', '=', clientId).executeTakeFirst()
        if (!row) return undefined
        return { ...parse<Client>(row.data), createdAt: new Date(row.created_at), updatedAt: new Date(row.updated_at) }
      },
      async create(client) {
        await db
          .insertInto('oidc_clients')
          .values({
            client_id: client.clientId,
            data: json(client),
            created_at: client.createdAt.getTime(),
            updated_at: client.updatedAt.getTime()
          })
          .execute()
      },
      async update(clientId, patch) {
        const row = await db.selectFrom('oidc_clients').selectAll().where('client_id', '=', clientId).executeTakeFirst()
        if (!row) return
        await db
          .updateTable('oidc_clients')
          .set({ data: json({ ...parse<Client>(row.data), ...patch }), updated_at: now() })
          .where('client_id', '=', clientId)
          .execute()
      },
      async destroy(clientId) {
        await db.deleteFrom('oidc_clients').where('client_id', '=', clientId).execute()
      },
      async list() {
        const rows = await db.selectFrom('oidc_clients').selectAll().execute()
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
        const row = await db.selectFrom('oidc_sessions').selectAll().where('id', '=', id).where('expires_at', '>', now()).executeTakeFirst()
        return row ? toSession(row) : undefined
      },
      async findByAccount(accountId) {
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
          .execute()
        return rows.map(toSession)
      },
      async upsert(session) {
        const row = {
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
        await db
          .insertInto('oidc_sessions')
          .values(row)
          .onConflict(conflict => conflict.column('id').doUpdateSet(row))
          .execute()
      },
      async destroy(id) {
        await db.deleteFrom('oidc_sessions').where('id', '=', id).execute()
      }
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
        const row = {
          id: grant.id,
          account_id: grant.accountId,
          client_id: grant.clientId,
          scopes: json(grant.scopes),
          claims: json(grant.claims),
          resources: json(grant.resources),
          created_at: grant.createdAt.getTime(),
          expires_at: grant.expiresAt ? grant.expiresAt.getTime() : null
        }
        await db
          .insertInto('oidc_grants')
          .values(row)
          .onConflict(conflict => conflict.column('id').doUpdateSet(row))
          .execute()
      },
      async destroy(id) {
        await db.deleteFrom('oidc_grants').where('id', '=', id).execute()
      }
    },

    accounts: options.accounts,
    keys: options.keys,

    replay: {
      async claim(namespace, value, ttl) {
        const existing = await db
          .selectFrom('oidc_replay')
          .selectAll()
          .where('namespace', '=', namespace)
          .where('value', '=', value)
          .where('expires_at', '>', now())
          .executeTakeFirst()
        if (existing) return false
        const expires_at = now() + ttl * 1000
        await db
          .insertInto('oidc_replay')
          .values({ namespace, value, expires_at })
          .onConflict(conflict => conflict.columns(['namespace', 'value']).doUpdateSet({ expires_at }))
          .execute()
        return true
      }
    },

    ...(federation && {
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
        async link(identity: FederatedIdentity) {
          const row = {
            provider: identity.provider,
            subject: identity.subject,
            account_id: identity.accountId,
            email: identity.email ?? null,
            claims: json(identity.claims),
            linked_at: identity.linkedAt.getTime()
          }
          await db
            .insertInto('oidc_identities')
            .values(row)
            .onConflict(conflict => conflict.columns(['provider', 'subject']).doUpdateSet(row))
            .execute()
        },
        async unlink(accountId: string, provider: string) {
          await db.deleteFrom('oidc_identities').where('account_id', '=', accountId).where('provider', '=', provider).execute()
        }
      }
    })
  }
}

export type { OidcraftDatabase } from './schema'
export * from './schema'
