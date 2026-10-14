/// <reference types="bun" />
import { Database } from 'bun:sqlite'
import { mkdirSync } from 'node:fs'
import { dirname } from 'node:path'
import { drizzle } from 'drizzle-orm/bun-sqlite'
import { type AccountStore, type Adapter, generatedKeyStore, type KeyStore } from 'oidcraft'
import { type DrizzleDatabase, drizzleAdapter, SQLITE_MIGRATIONS } from 'oidcraft/adapters/drizzle'
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

type StorageOptions = { accounts: AccountStore; federation: boolean; keys: KeyStore | undefined }

/** OIDCRAFT_DB names a SQLite file; `memory` keeps nothing, which is what a conformance run wants. */
export const openStorage = async ({ accounts, federation, keys }: StorageOptions): Promise<Adapter> => {
  const location = withDefault('OIDCRAFT_DB', 'data/oidcraft.sqlite')
  if (location === 'memory') return memoryAdapter({ accounts, federation, ...(keys && { keys }) })

  mkdirSync(dirname(location), { recursive: true })
  const sqlite = new Database(location, { create: true })
  sqlite.run('pragma journal_mode = wal')
  migrate(sqlite)
  console.log(`[oidcraft] storing in ${location}`)
  return drizzleAdapter({
    db: drizzle(sqlite) as unknown as DrizzleDatabase,
    accounts,
    federation,
    keys: keys ?? (await generatedKeyStore())
  })
}
