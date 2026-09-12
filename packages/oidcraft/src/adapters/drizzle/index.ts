import { and, eq, gt, isNull, lte, or, sql } from 'drizzle-orm'
import type { BaseSQLiteDatabase } from 'drizzle-orm/sqlite-core'
import type { AccountStore, Adapter, Artifact, ArtifactKind, Client, FederatedIdentity, Grant, KeyStore, Session } from 'oidcraft'
import { artifacts, clients, grants, identities, replay, sessions } from './schema'

export type DrizzleDatabase = BaseSQLiteDatabase<'sync' | 'async', unknown, Record<string, never>>

export type DrizzleAdapterOptions = {
  db: DrizzleDatabase
  keys: KeyStore
  accounts: AccountStore
  federation?: boolean
}

const now = () => new Date()

/** FR-T5: enforced by the query, so a missed prune still cannot serve an expired row. */
const live = (column: typeof artifacts.expiresAt) => gt(column, now())

export const drizzleAdapter = (options: DrizzleAdapterOptions): Adapter => {
  const db = options.db

  const toArtifact = (row: typeof artifacts.$inferSelect): Artifact => ({
    id: row.id,
    kind: row.kind as ArtifactKind,
    clientId: row.clientId,
    ...(row.accountId && { accountId: row.accountId }),
    ...(row.grantId && { grantId: row.grantId }),
    payload: row.payload as Record<string, unknown>,
    ...(row.consumedAt && { consumedAt: row.consumedAt }),
    expiresAt: row.expiresAt
  })

  const toSession = (row: typeof sessions.$inferSelect): Session => ({
    id: row.id,
    accountId: row.accountId,
    authTime: row.authTime,
    ...(row.acr && { acr: row.acr }),
    ...(row.amr ? { amr: row.amr as string[] } : {}),
    ...(row.idp && { idp: row.idp }),
    ...(row.upstreamSessionId && { upstreamSessionId: row.upstreamSessionId }),
    clients: row.clients as string[],
    expiresAt: row.expiresAt
  })

  const toGrant = (row: typeof grants.$inferSelect): Grant => ({
    id: row.id,
    accountId: row.accountId,
    clientId: row.clientId,
    scopes: row.scopes as string[],
    claims: row.claims as string[],
    resources: row.resources as Record<string, string[]>,
    createdAt: row.createdAt,
    ...(row.expiresAt && { expiresAt: row.expiresAt })
  })

  const federation = options.federation !== false

  return {
    clients: {
      async find(clientId) {
        const [row] = await db.select().from(clients).where(eq(clients.clientId, clientId)).limit(1)
        return row
          ? ({ ...(row.data as Record<string, unknown>), createdAt: row.createdAt, updatedAt: row.updatedAt } as Client)
          : undefined
      },
      async create(client) {
        await db
          .insert(clients)
          .values({ clientId: client.clientId, data: client, createdAt: client.createdAt, updatedAt: client.updatedAt })
      },
      async update(clientId, patch) {
        const [row] = await db.select().from(clients).where(eq(clients.clientId, clientId)).limit(1)
        if (!row) return
        const merged = { ...(row.data as Record<string, unknown>), ...patch }
        await db.update(clients).set({ data: merged, updatedAt: now() }).where(eq(clients.clientId, clientId))
      },
      async destroy(clientId) {
        await db.delete(clients).where(eq(clients.clientId, clientId))
      },
      async list() {
        const rows = await db.select().from(clients)
        return {
          clients: rows.map(
            row => ({ ...(row.data as Record<string, unknown>), createdAt: row.createdAt, updatedAt: row.updatedAt }) as Client
          )
        }
      }
    },

    artifacts: {
      async upsert(artifact) {
        const row = {
          kind: artifact.kind,
          id: artifact.id,
          clientId: artifact.clientId,
          accountId: artifact.accountId ?? null,
          grantId: artifact.grantId ?? null,
          userCode: (artifact.payload.userCode as string | undefined) ?? null,
          payload: artifact.payload,
          consumedAt: artifact.consumedAt ?? null,
          expiresAt: artifact.expiresAt
        }
        await db
          .insert(artifacts)
          .values(row)
          .onConflictDoUpdate({ target: [artifacts.kind, artifacts.id], set: row })
      },
      async find(kind, id) {
        const [row] = await db
          .select()
          .from(artifacts)
          .where(and(eq(artifacts.kind, kind), eq(artifacts.id, id), live(artifacts.expiresAt)))
          .limit(1)
        return row ? toArtifact(row) : undefined
      },
      async findByUserCode(userCode) {
        const [row] = await db
          .select()
          .from(artifacts)
          .where(and(eq(artifacts.userCode, userCode), live(artifacts.expiresAt)))
          .limit(1)
        return row ? toArtifact(row) : undefined
      },
      async consume(kind, id) {
        await db
          .update(artifacts)
          .set({ consumedAt: now() })
          .where(and(eq(artifacts.kind, kind), eq(artifacts.id, id)))
      },
      async destroy(kind, id) {
        await db.delete(artifacts).where(and(eq(artifacts.kind, kind), eq(artifacts.id, id)))
      },
      async revokeByGrantId(grantId) {
        // One indexed delete, not a scan — this is the whole point of a relational adapter (FR-A5).
        await db.delete(artifacts).where(eq(artifacts.grantId, grantId))
      },
      async prune(before, limit) {
        const doomed = await db
          .select({ kind: artifacts.kind, id: artifacts.id })
          .from(artifacts)
          .where(lte(artifacts.expiresAt, before))
          .limit(limit)
        for (const row of doomed) await db.delete(artifacts).where(and(eq(artifacts.kind, row.kind), eq(artifacts.id, row.id)))
        return doomed.length
      }
    },

    sessions: {
      async find(id) {
        const [row] = await db
          .select()
          .from(sessions)
          .where(and(eq(sessions.id, id), gt(sessions.expiresAt, now())))
          .limit(1)
        return row ? toSession(row) : undefined
      },
      async findByAccount(accountId) {
        const rows = await db
          .select()
          .from(sessions)
          .where(and(eq(sessions.accountId, accountId), gt(sessions.expiresAt, now())))
        return rows.map(toSession)
      },
      async findByUpstreamSession(provider, upstreamSessionId) {
        const rows = await db
          .select()
          .from(sessions)
          .where(and(eq(sessions.idp, provider), eq(sessions.upstreamSessionId, upstreamSessionId)))
        return rows.map(toSession)
      },
      async upsert(session) {
        const row = {
          id: session.id,
          accountId: session.accountId,
          authTime: session.authTime,
          acr: session.acr ?? null,
          amr: session.amr ?? null,
          idp: session.idp ?? null,
          upstreamSessionId: session.upstreamSessionId ?? null,
          clients: session.clients,
          expiresAt: session.expiresAt
        }
        await db.insert(sessions).values(row).onConflictDoUpdate({ target: sessions.id, set: row })
      },
      async destroy(id) {
        await db.delete(sessions).where(eq(sessions.id, id))
      }
    },

    grants: {
      async find(id) {
        const [row] = await db.select().from(grants).where(eq(grants.id, id)).limit(1)
        return row ? toGrant(row) : undefined
      },
      async findByAccountAndClient(accountId, clientId) {
        const [row] = await db
          .select()
          .from(grants)
          .where(and(eq(grants.accountId, accountId), eq(grants.clientId, clientId)))
          .limit(1)
        return row ? toGrant(row) : undefined
      },
      async listForAccount(accountId) {
        return (await db.select().from(grants).where(eq(grants.accountId, accountId))).map(toGrant)
      },
      async upsert(grant) {
        const row = {
          id: grant.id,
          accountId: grant.accountId,
          clientId: grant.clientId,
          scopes: grant.scopes,
          claims: grant.claims,
          resources: grant.resources,
          createdAt: grant.createdAt,
          expiresAt: grant.expiresAt ?? null
        }
        await db.insert(grants).values(row).onConflictDoUpdate({ target: grants.id, set: row })
      },
      async destroy(id) {
        await db.delete(grants).where(eq(grants.id, id))
      }
    },

    accounts: options.accounts,
    keys: options.keys,

    replay: {
      async claim(namespace, value, ttl) {
        const [existing] = await db
          .select()
          .from(replay)
          .where(and(eq(replay.namespace, namespace), eq(replay.value, value), gt(replay.expiresAt, now())))
          .limit(1)
        if (existing) return false
        await db
          .insert(replay)
          .values({ namespace, value, expiresAt: new Date(Date.now() + ttl * 1000) })
          .onConflictDoUpdate({ target: [replay.namespace, replay.value], set: { expiresAt: new Date(Date.now() + ttl * 1000) } })
        return true
      }
    },

    ...(federation && {
      identities: {
        async find(provider: string, subject: string) {
          const [row] = await db
            .select()
            .from(identities)
            .where(and(eq(identities.provider, provider), eq(identities.subject, subject)))
            .limit(1)
          return row ? toIdentity(row) : undefined
        },
        async listForAccount(accountId: string) {
          return (await db.select().from(identities).where(eq(identities.accountId, accountId))).map(toIdentity)
        },
        async link(identity: FederatedIdentity) {
          const row = {
            provider: identity.provider,
            subject: identity.subject,
            accountId: identity.accountId,
            email: identity.email ?? null,
            claims: identity.claims,
            linkedAt: identity.linkedAt
          }
          await db
            .insert(identities)
            .values(row)
            .onConflictDoUpdate({ target: [identities.provider, identities.subject], set: row })
        },
        async unlink(accountId: string, provider: string) {
          await db.delete(identities).where(and(eq(identities.accountId, accountId), eq(identities.provider, provider)))
        }
      }
    })
  }
}

const toIdentity = (row: typeof identities.$inferSelect): FederatedIdentity => ({
  accountId: row.accountId,
  provider: row.provider,
  subject: row.subject,
  ...(row.email && { email: row.email }),
  claims: row.claims as Record<string, unknown>,
  linkedAt: row.linkedAt
})

export * from './schema'
export { schema } from './schema'
