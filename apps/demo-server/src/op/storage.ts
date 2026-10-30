/// <reference types="bun" />
import { Database } from 'bun:sqlite'
import { mkdirSync } from 'node:fs'
import { dirname } from 'node:path'
import { SQL } from 'bun'
import { drizzle as drizzlePostgres } from 'drizzle-orm/bun-sql'
import { drizzle } from 'drizzle-orm/bun-sqlite'
import { type FullAdapter, generatedKeyStore, type KeyStore } from 'oidcraft'
import { drizzleAdapter, POSTGRES_MIGRATIONS, postgresTables, SQLITE_MIGRATIONS } from 'oidcraft/adapters/drizzle'
import { memoryAdapter } from 'oidcraft/adapters/memory'
import { withDefault } from './env'

/**
 * This app is the host, so applying the library's migrations is its call (FR-A4). It runs one
 * process, so doing it at boot is safe here; a deployment with several runs them before rollout.
 */
const migrate = (sqlite: Database) => {
  sqlite.run('create table if not exists demo_migrations (id text primary key, applied_at integer not null)')
  const applied = new Set(
    sqlite
      .query<{ id: string }, []>('select id from demo_migrations')
      .all()
      .map(row => row.id)
  )
  for (const migration of SQLITE_MIGRATIONS) {
    if (applied.has(migration.id)) continue
    sqlite.transaction(() => {
      for (const statement of migration.statements) sqlite.run(statement)
      sqlite.run('insert into demo_migrations (id, applied_at) values (?, ?)', [migration.id, Date.now()])
    })()
  }
}

export const isPostgres = (location: string) => /^postgres(ql)?:\/\//.test(location)

// One connection pool per database, shared by the control plane and every realm's schema in it.
const pools = new Map<string, SQL>()
const poolFor = (url: string) => {
  let pool = pools.get(url)
  if (!pool) {
    pool = new SQL(url)
    pools.set(url, pool)
  }
  return pool
}

/** The same, for a Postgres schema: its own migrations table, and the tables land where the search path says. */
const migratePostgres = async (sql: SQL, schema: string) => {
  await sql.unsafe(`create schema if not exists ${schema}`)
  await sql.unsafe(`create table if not exists ${schema}.demo_migrations (id text primary key, applied_at bigint not null)`)
  const applied = new Set((await sql.unsafe(`select id from ${schema}.demo_migrations`)).map((row: { id: string }) => row.id))
  for (const migration of POSTGRES_MIGRATIONS) {
    if (applied.has(migration.id)) continue
    await sql.begin(async tx => {
      await tx.unsafe(`set local search_path to ${schema}`)
      for (const statement of migration.statements) await tx.unsafe(statement)
      await tx.unsafe(`insert into ${schema}.demo_migrations (id, applied_at) values ($1, $2)`, [migration.id, Date.now()])
    })
  }
}

/** A realm's schema has its own tables, in the one database; retiring the realm drops it (G-6). */
export const dropPostgresSchema = (url: string, schema: string) => poolFor(url).unsafe(`drop schema if exists ${schema} cascade`)

type StorageOptions = { keys: KeyStore | undefined; schema?: string }

/**
 * A SQLite file at `location`, migrated; a Postgres schema when it is a postgres:// URL (`public`
 * unless named); or nothing kept at all when it is `memory`.
 */
export const openAdapter = async (location: string, { keys, schema }: StorageOptions): Promise<FullAdapter> => {
  if (location === 'memory') return memoryAdapter({ ...(keys && { keys }) })
  if (isPostgres(location)) {
    const sql = poolFor(location)
    await migratePostgres(sql, schema ?? 'public')
    return drizzleAdapter({
      db: drizzlePostgres({ client: sql }),
      tables: postgresTables(schema),
      keys: keys ?? (await generatedKeyStore())
    })
  }
  mkdirSync(dirname(location), { recursive: true })
  const sqlite = new Database(location, { create: true })
  sqlite.run('pragma journal_mode = wal')
  migrate(sqlite)
  return drizzleAdapter({ db: drizzle({ client: sqlite }), keys: keys ?? (await generatedKeyStore()) })
}

/** OIDCRAFT_DB names a SQLite file or a postgres:// URL; `memory` keeps nothing, which is what a conformance run wants. */
export const storageLocation = () => withDefault('OIDCRAFT_DB', 'data/oidcraft.sqlite')

export const openStorage = async (options: StorageOptions): Promise<FullAdapter> => {
  const location = storageLocation()
  if (location !== 'memory') console.log(`[oidcraft] storing in ${location.replace(/\/\/[^@/]*@/, '//***@')}`)
  return openAdapter(location, options)
}
