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
  Passkey,
  Realm,
  Session
} from '@oidcraft/adapter'
import { grantExpired, MERGE_ROUNDS, mergedGrant, noAccounts } from '@oidcraft/adapter'
import { replayDigest } from '@oidcraft/sql/rows'
import { type AnyRelations, and, eq, gt, inArray, is, isNull, lte, or, type SQL, sql } from 'drizzle-orm'
import { MySqlTable } from 'drizzle-orm/mysql-core'
import type { PgQueryResultHKT } from 'drizzle-orm/pg-core'
import type { PgAsyncDatabase } from 'drizzle-orm/pg-core/async'
import type { SQLiteAsyncDatabase } from 'drizzle-orm/sqlite-core'
import type { MysqlTables } from './mysql-schema'
import type { PostgresTables } from './postgres-schema'
import { type artifacts, type credentials, type identities, type passkeys, type realms, schema } from './schema'

export type DrizzleDatabase = SQLiteAsyncDatabase<'sync' | 'async', unknown>

export type DrizzleAdapterOptions = {
  keys: KeyStore
  /** Omitted, every account lookup misses: the host composes one in later, as `@oidcraft/provider/accounts` does. */
  accounts?: AccountStore
} & (
  | { db: DrizzleDatabase; tables?: undefined }
  /** Postgres: the tables come from `postgresTables(schema?)`, which is where a realm's schema is chosen (G-6). */
  | { db: PgAsyncDatabase<PgQueryResultHKT, AnyRelations>; tables: PostgresTables }
  /** MySQL or MariaDB, one dialect, through `drizzle-orm/mysql2`: the tables come from `mysqlTables(database?)` (G-6). */
  | { db: unknown; tables: MysqlTables }
)

type Affected = [{ affectedRows: number }]

/** The writes MySQL spells its own way: no `RETURNING`, no `ON CONFLICT`, and `DELETE … LIMIT`. Reads are the same everywhere. */
type MysqlWrites = {
  insert(table: unknown): { values(row: unknown): Promise<unknown> & { onDuplicateKeyUpdate(config: { set: unknown }): Promise<unknown> } }
  update(table: unknown): { set(values: unknown): { where(condition: SQL | undefined): Promise<Affected> } }
  delete(table: unknown): { where(condition: SQL | undefined): { orderBy(column: unknown): { limit(limit: number): Promise<Affected> } } }
}

/** ER_DUP_ENTRY, the same on MySQL and MariaDB; Drizzle wraps the driver's error as its `cause`. */
const duplicateKey = (error: unknown): boolean =>
  typeof error === 'object' &&
  error !== null &&
  ((error as { errno?: unknown }).errno === 1062 || duplicateKey((error as { cause?: unknown }).cause))

const now = () => new Date()

/** FR-T5: enforced by the query, so a missed prune still cannot serve an expired row. */
const live = (column: typeof artifacts.expiresAt) => gt(column, now())

export const drizzleAdapter = (options: DrizzleAdapterOptions): FullAdapter => {
  // Typed as SQLite's: every query here is one both dialects accept, over the same columns and JS values (FR-A4).
  const db = options.db as DrizzleDatabase
  const { clients, artifacts, sessions, grants, identities, replay, credentials, passkeys, realms } = (options.tables ??
    schema) as typeof schema
  // FR-T5: a grant may carry an expiry, which the query enforces as it does an artifact's.
  const grantLive = () => or(isNull(grants.expiresAt), gt(grants.expiresAt, now()))
  // A host's connection may count matched rows as affected (CLIENT_FOUND_ROWS, mysql2's default): no count read here depends on which.
  const mysql = is(clients, MySqlTable) ? (options.db as MysqlWrites) : undefined

  /** Atomic: true for exactly one of racing writers (FR-A3). */
  const insertIfAbsentMysql = async (writes: MysqlWrites, table: unknown, row: unknown) => {
    try {
      await writes.insert(table).values(row)
      return true
    } catch (error) {
      if (duplicateKey(error)) return false
      throw error
    }
  }

  /** MySQL refuses a `LIMIT` in an `IN` subquery on the table being deleted from. */
  const pruneMysql = async (
    writes: MysqlWrites,
    table: typeof artifacts | typeof sessions | typeof replay,
    before: Date,
    limit: number
  ) => {
    const [result] = await writes.delete(table).where(lte(table.expiresAt, before)).orderBy(table.expiresAt).limit(limit)
    return result.affectedRows
  }

  const toArtifact = (row: typeof artifacts.$inferSelect): Artifact => ({
    id: row.id,
    kind: row.kind as ArtifactKind,
    clientId: row.clientId,
    ...(row.accountId && { accountId: row.accountId }),
    ...(row.grantId && { grantId: row.grantId }),
    ...(row.familyId && { familyId: row.familyId }),
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

  const grantRow = (grant: Grant) => ({
    id: grant.id,
    accountId: grant.accountId,
    clientId: grant.clientId,
    scopes: grant.scopes,
    claims: grant.claims,
    resources: grant.resources,
    createdAt: grant.createdAt,
    expiresAt: grant.expiresAt ?? null
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

  return {
    clients: {
      async find(clientId) {
        const [row] = await db.select().from(clients).where(eq(clients.clientId, clientId)).limit(1)
        return row
          ? ({ ...(row.data as Record<string, unknown>), createdAt: row.createdAt, updatedAt: row.updatedAt } as Client)
          : undefined
      },
      async upsert(client) {
        const row = { clientId: client.clientId, data: client, createdAt: client.createdAt, updatedAt: client.updatedAt }
        const set = { data: client, updatedAt: client.updatedAt }
        if (mysql) await mysql.insert(clients).values(row).onDuplicateKeyUpdate({ set })
        else await db.insert(clients).values(row).onConflictDoUpdate({ target: clients.clientId, set })
      },
      async destroy(clientId) {
        await db.delete(clients).where(eq(clients.clientId, clientId))
      },
      async list(cursor, limit) {
        const ordered = db
          .select()
          .from(clients)
          .where(cursor === undefined ? undefined : gt(clients.clientId, cursor))
          .orderBy(clients.clientId)
        const rows = await (limit === undefined ? ordered : ordered.limit(limit + 1))
        const more = limit !== undefined && rows.length > limit
        const shown = more ? rows.slice(0, limit) : rows
        return {
          clients: shown.map(
            row => ({ ...(row.data as Record<string, unknown>), createdAt: row.createdAt, updatedAt: row.updatedAt }) as Client
          ),
          ...(more && { cursor: shown.at(-1)?.clientId as string })
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
          familyId: artifact.familyId ?? null,
          userCode: (artifact.payload.userCode as string | undefined) ?? null,
          payload: artifact.payload,
          consumedAt: artifact.consumedAt ?? null,
          expiresAt: artifact.expiresAt
        }
        const set = { ...row, consumedAt: undefined }
        if (mysql) await mysql.insert(artifacts).values(row).onDuplicateKeyUpdate({ set })
        else
          await db
            .insert(artifacts)
            .values(row)
            .onConflictDoUpdate({ target: [artifacts.kind, artifacts.id], set })
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
        const unconsumed = and(eq(artifacts.kind, kind), eq(artifacts.id, id), isNull(artifacts.consumedAt), live(artifacts.expiresAt))
        if (mysql) return (await mysql.update(artifacts).set({ consumedAt: now() }).where(unconsumed))[0].affectedRows === 1
        const won = await db.update(artifacts).set({ consumedAt: now() }).where(unconsumed).returning({ id: artifacts.id })
        return won.length === 1
      },
      async destroy(kind, id) {
        await db.delete(artifacts).where(and(eq(artifacts.kind, kind), eq(artifacts.id, id)))
      },
      async revokeByGrantId(grantId) {
        // One indexed delete, not a scan (FR-A5).
        await db.delete(artifacts).where(eq(artifacts.grantId, grantId))
      },
      async revokeByFamilyId(familyId) {
        await db.delete(artifacts).where(eq(artifacts.familyId, familyId))
      },
      async revokeByClientId(clientId) {
        await db.delete(artifacts).where(eq(artifacts.clientId, clientId))
      },
      async prune(before, limit) {
        if (mysql) return pruneMysql(mysql, artifacts, before, limit)
        const doomed = db
          .select({ kind: artifacts.kind, id: artifacts.id })
          .from(artifacts)
          .where(lte(artifacts.expiresAt, before))
          .limit(limit)
        // One bounded statement, expired still at the delete: a row rewritten since the select is live again (NFR-P3).
        const gone = await db
          .delete(artifacts)
          .where(and(sql`(${artifacts.kind}, ${artifacts.id}) in ${doomed}`, lte(artifacts.expiresAt, before)))
          .returning({ id: artifacts.id })
        return gone.length
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
      async listForAccount(accountId) {
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
          .where(and(eq(sessions.idp, provider), eq(sessions.upstreamSessionId, upstreamSessionId), gt(sessions.expiresAt, now())))
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
        if (mysql) await mysql.insert(sessions).values(row).onDuplicateKeyUpdate({ set: row })
        else await db.insert(sessions).values(row).onConflictDoUpdate({ target: sessions.id, set: row })
      },
      // Compare-and-swap, retried while another writer wins, so concurrent sign-ins are all recorded (FR-C11).
      async addClient(id, clientId) {
        for (let attempt = 0; attempt < 64; attempt++) {
          const [row] = await db.select({ clients: sessions.clients }).from(sessions).where(eq(sessions.id, id)).limit(1)
          if (!row) return
          const current = row.clients as string[]
          if (current.includes(clientId)) return
          const unchanged = and(eq(sessions.id, id), eq(sessions.clients, current))
          const added = [...current, clientId]
          if (mysql) {
            if ((await mysql.update(sessions).set({ clients: added }).where(unchanged))[0].affectedRows) return
            continue
          }
          const updated = await db.update(sessions).set({ clients: added }).where(unchanged).returning({ id: sessions.id })
          if (updated.length) return
        }
        throw new Error(`session ${id} kept changing; its client list could not be updated`)
      },
      async destroy(id) {
        await db.delete(sessions).where(eq(sessions.id, id))
      },
      async prune(before, limit) {
        if (mysql) return pruneMysql(mysql, sessions, before, limit)
        const doomed = db.select({ id: sessions.id }).from(sessions).where(lte(sessions.expiresAt, before)).limit(limit)
        const gone = await db
          .delete(sessions)
          .where(and(inArray(sessions.id, doomed), lte(sessions.expiresAt, before)))
          .returning({ id: sessions.id })
        return gone.length
      }
    },

    grants: {
      async find(id) {
        const [row] = await db
          .select()
          .from(grants)
          .where(and(eq(grants.id, id), grantLive()))
          .limit(1)
        return row ? toGrant(row) : undefined
      },
      async findByAccountAndClient(accountId, clientId) {
        const [row] = await db
          .select()
          .from(grants)
          .where(and(eq(grants.accountId, accountId), eq(grants.clientId, clientId), grantLive()))
          .limit(1)
        return row ? toGrant(row) : undefined
      },
      async listForAccount(accountId) {
        return (
          await db
            .select()
            .from(grants)
            .where(and(eq(grants.accountId, accountId), grantLive()))
        ).map(toGrant)
      },
      async upsert(grant) {
        const row = grantRow(grant)
        const { id: _id, createdAt: _createdAt, ...changed } = row
        if (mysql) await mysql.insert(grants).values(row).onDuplicateKeyUpdate({ set: changed })
        else
          await db
            .insert(grants)
            .values(row)
            .onConflictDoUpdate({ target: [grants.accountId, grants.clientId], set: changed })
      },
      // FR-I4: compare-and-swap on what was read, so a consent landing between the read and the write is never overwritten.
      async merge(grant) {
        for (let round = 0; round < MERGE_ROUNDS; round++) {
          const [row] = await db
            .select()
            .from(grants)
            .where(and(eq(grants.accountId, grant.accountId), eq(grants.clientId, grant.clientId)))
            .limit(1)
          if (!row) {
            const won = mysql
              ? await insertIfAbsentMysql(mysql, grants, grantRow(grant))
              : (await db.insert(grants).values(grantRow(grant)).onConflictDoNothing().returning({ id: grants.id })).length === 1
            if (won) return grant
            continue
          }
          const held = toGrant(row)
          if (grantExpired(held)) {
            await db.delete(grants).where(and(eq(grants.id, held.id), lte(grants.expiresAt, now())))
            continue
          }
          const merged = mergedGrant(held, grant)
          const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b)
          // Nothing new: an update that changes nothing counts no row without CLIENT_FOUND_ROWS, and would look like a lost race.
          if (same(merged.scopes, held.scopes) && same(merged.claims, held.claims) && same(merged.resources, held.resources)) return held
          const set = { scopes: merged.scopes, claims: merged.claims, resources: merged.resources }
          const unchanged = and(
            eq(grants.id, held.id),
            eq(grants.scopes, row.scopes),
            eq(grants.claims, row.claims),
            eq(grants.resources, row.resources)
          )
          const swapped = mysql
            ? (await mysql.update(grants).set(set).where(unchanged))[0].affectedRows
            : (await db.update(grants).set(set).where(unchanged).returning({ id: grants.id })).length
          if (swapped) return merged
        }
        throw new Error(`the grant for ${grant.accountId} and ${grant.clientId} kept changing under the merge`)
      },
      async destroy(id) {
        await db.delete(grants).where(eq(grants.id, id))
      },
      async destroyByClientId(clientId) {
        await db.delete(grants).where(eq(grants.clientId, clientId))
      }
    },

    accounts: options.accounts ?? noAccounts,
    keys: options.keys,

    replay: {
      async claim(namespace, value, ttl) {
        const expiresAt = new Date(Date.now() + ttl * 1000)
        if (mysql) {
          // NFR-S5: a client chooses its jti's length, and a MySQL key's is fixed.
          const key = await replayDigest(value)
          // Only a lapsed claim is cleared, so the insert is what decides between racing claimers.
          await db.delete(replay).where(and(eq(replay.namespace, namespace), eq(replay.value, key), lte(replay.expiresAt, now())))
          return insertIfAbsentMysql(mysql, replay, { namespace, value: key, expiresAt })
        }
        // One statement: a fresh row is inserted, a lapsed one is taken over, a live one is left alone.
        const won = await db
          .insert(replay)
          .values({ namespace, value, expiresAt })
          .onConflictDoUpdate({ target: [replay.namespace, replay.value], set: { expiresAt }, setWhere: lte(replay.expiresAt, now()) })
          .returning({ value: replay.value })
        return won.length === 1
      },
      async prune(before, limit) {
        if (mysql) return pruneMysql(mysql, replay, before, limit)
        const doomed = db
          .select({ namespace: replay.namespace, value: replay.value })
          .from(replay)
          .where(lte(replay.expiresAt, before))
          .limit(limit)
        const gone = await db
          .delete(replay)
          .where(and(sql`(${replay.namespace}, ${replay.value}) in ${doomed}`, lte(replay.expiresAt, before)))
          .returning({ value: replay.value })
        return gone.length
      }
    },

    credentials: {
      async find(accountId: string) {
        const [row] = await db.select().from(credentials).where(eq(credentials.accountId, accountId)).limit(1)
        return row ? toCredential(row) : undefined
      },
      async findByUsername(username: string) {
        const [row] = await db.select().from(credentials).where(eq(credentials.username, username)).limit(1)
        return row ? toCredential(row) : undefined
      },
      // Both the key and the username are unique, and DO NOTHING without a target covers either.
      async create(credential: Credential) {
        if (mysql) return insertIfAbsentMysql(mysql, credentials, credentialRow(credential))
        const won = await db
          .insert(credentials)
          .values(credentialRow(credential))
          .onConflictDoNothing()
          .returning({ id: credentials.accountId })
        return won.length === 1
      },
      async upsert(credential: Credential) {
        const row = credentialRow(credential)
        if (!mysql) {
          await db.insert(credentials).values(row).onConflictDoUpdate({ target: credentials.accountId, set: row })
          return
        }
        // ON DUPLICATE KEY UPDATE answers a clash on the username too, by rewriting the other account's row; this throws.
        const [held] = await db
          .select({ accountId: credentials.accountId })
          .from(credentials)
          .where(eq(credentials.accountId, row.accountId))
          .limit(1)
        if (!held) {
          await mysql.insert(credentials).values(row)
          return
        }
        const { accountId, ...rest } = row
        await mysql.update(credentials).set(rest).where(eq(credentials.accountId, accountId))
      },
      async destroy(accountId: string) {
        await db.delete(credentials).where(eq(credentials.accountId, accountId))
      }
    },

    passkeys: {
      async find(credentialId: string) {
        const [row] = await db.select().from(passkeys).where(eq(passkeys.credentialId, credentialId)).limit(1)
        return row ? toPasskey(row) : undefined
      },
      async listForAccount(accountId: string) {
        return (await db.select().from(passkeys).where(eq(passkeys.accountId, accountId))).map(toPasskey)
      },
      async create(passkey: Passkey) {
        if (mysql) return insertIfAbsentMysql(mysql, passkeys, passkeyRow(passkey))
        const won = await db.insert(passkeys).values(passkeyRow(passkey)).onConflictDoNothing().returning({ id: passkeys.credentialId })
        return won.length === 1
      },
      async upsert(passkey: Passkey) {
        const row = passkeyRow(passkey)
        if (mysql) await mysql.insert(passkeys).values(row).onDuplicateKeyUpdate({ set: row })
        else await db.insert(passkeys).values(row).onConflictDoUpdate({ target: passkeys.credentialId, set: row })
      },
      async destroy(credentialId: string) {
        await db.delete(passkeys).where(eq(passkeys.credentialId, credentialId))
      }
    },

    realms: {
      async find(id: string) {
        const [row] = await db.select().from(realms).where(eq(realms.id, id)).limit(1)
        return row ? toRealm(row) : undefined
      },
      async list() {
        return (await db.select().from(realms)).map(toRealm)
      },
      async create(realm: Realm) {
        if (mysql) return insertIfAbsentMysql(mysql, realms, realmRow(realm))
        const won = await db.insert(realms).values(realmRow(realm)).onConflictDoNothing().returning({ id: realms.id })
        return won.length === 1
      },
      async upsert(realm: Realm) {
        const row = realmRow(realm)
        if (mysql) await mysql.insert(realms).values(row).onDuplicateKeyUpdate({ set: row })
        else await db.insert(realms).values(row).onConflictDoUpdate({ target: realms.id, set: row })
      },
      async destroy(id: string) {
        await db.delete(realms).where(eq(realms.id, id))
      }
    },

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
      async upsert(identity: LinkedIdentity) {
        const row = {
          provider: identity.provider,
          subject: identity.subject,
          accountId: identity.accountId,
          email: identity.email ?? null,
          claims: identity.claims,
          linkedAt: identity.linkedAt
        }
        if (mysql) await mysql.insert(identities).values(row).onDuplicateKeyUpdate({ set: row })
        else
          await db
            .insert(identities)
            .values(row)
            .onConflictDoUpdate({ target: [identities.provider, identities.subject], set: row })
      },
      async destroy(provider: string, subject: string) {
        await db.delete(identities).where(and(eq(identities.provider, provider), eq(identities.subject, subject)))
      }
    }
  }
}

const credentialRow = (credential: Credential) => ({
  accountId: credential.accountId,
  username: credential.username,
  passwordHash: credential.passwordHash,
  claims: credential.claims,
  totpSecret: credential.totp?.secret ?? null,
  totpConfirmedAt: credential.totp?.confirmedAt ?? null,
  recoveryCodes: credential.recoveryCodes ?? null,
  failedAttempts: credential.failedAttempts,
  lockedUntil: credential.lockedUntil ?? null,
  createdAt: credential.createdAt,
  updatedAt: credential.updatedAt
})

const toCredential = (row: typeof credentials.$inferSelect): Credential => ({
  accountId: row.accountId,
  username: row.username,
  passwordHash: row.passwordHash,
  claims: row.claims as Record<string, unknown>,
  ...(row.totpSecret && { totp: { secret: row.totpSecret, ...(row.totpConfirmedAt && { confirmedAt: row.totpConfirmedAt }) } }),
  ...(row.recoveryCodes ? { recoveryCodes: row.recoveryCodes as string[] } : {}),
  failedAttempts: row.failedAttempts,
  ...(row.lockedUntil && { lockedUntil: row.lockedUntil }),
  createdAt: row.createdAt,
  updatedAt: row.updatedAt
})

const passkeyRow = (passkey: Passkey) => ({
  credentialId: passkey.credentialId,
  accountId: passkey.accountId,
  publicKey: passkey.publicKey,
  algorithm: passkey.algorithm,
  counter: passkey.counter,
  transports: passkey.transports,
  name: passkey.name,
  createdAt: passkey.createdAt,
  lastUsedAt: passkey.lastUsedAt ?? null
})

const toPasskey = (row: typeof passkeys.$inferSelect): Passkey => ({
  credentialId: row.credentialId,
  accountId: row.accountId,
  publicKey: row.publicKey,
  algorithm: row.algorithm,
  counter: row.counter,
  transports: row.transports as string[],
  name: row.name,
  createdAt: row.createdAt,
  ...(row.lastUsedAt && { lastUsedAt: row.lastUsedAt })
})

const realmRow = (realm: Realm) => ({
  id: realm.id,
  displayName: realm.displayName ?? null,
  enabled: realm.enabled,
  settings: realm.settings,
  createdAt: realm.createdAt,
  updatedAt: realm.updatedAt
})

const toRealm = (row: typeof realms.$inferSelect): Realm => ({
  id: row.id,
  ...(row.displayName && { displayName: row.displayName }),
  enabled: row.enabled,
  settings: row.settings as Record<string, unknown>,
  createdAt: row.createdAt,
  updatedAt: row.updatedAt
})

const toIdentity = (row: typeof identities.$inferSelect): LinkedIdentity => ({
  accountId: row.accountId,
  provider: row.provider,
  subject: row.subject,
  ...(row.email && { email: row.email }),
  claims: row.claims as Record<string, unknown>,
  linkedAt: row.linkedAt
})

export { MYSQL_MIGRATIONS } from '@oidcraft/sql/mysql'
export { POSTGRES_MIGRATIONS } from '@oidcraft/sql/postgres'
export { type Migration, SQLITE_MIGRATIONS } from '@oidcraft/sql/sqlite'
export { type MysqlTables, mysqlTables } from './mysql-schema'
export { type PostgresTables, postgresTables } from './postgres-schema'
export * from './schema'
export { schema } from './schema'
