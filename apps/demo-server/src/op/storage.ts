/// <reference types="bun" />
import { Database } from 'bun:sqlite'
import { mkdirSync } from 'node:fs'
import { dirname } from 'node:path'
import { drizzle } from 'drizzle-orm/bun-sqlite'
import { type Adapter, generatedKeyStore, type KeyStore } from 'oidcraft'
import { drizzleAdapter, SQLITE_MIGRATIONS } from 'oidcraft/adapters/drizzle'
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

type StorageOptions = { federation: boolean; keys: KeyStore | undefined }

/** A SQLite file at `location`, migrated, or nothing kept at all when it is `memory`. */
export const openAdapter = async (location: string, { federation, keys }: StorageOptions): Promise<Adapter> => {
  if (location === 'memory') return memoryAdapter({ federation, ...(keys && { keys }) })
  mkdirSync(dirname(location), { recursive: true })
  const sqlite = new Database(location, { create: true })
  sqlite.run('pragma journal_mode = wal')
  migrate(sqlite)
  return drizzleAdapter({ db: drizzle({ client: sqlite }), federation, keys: keys ?? (await generatedKeyStore()) })
}

/** OIDCRAFT_DB names a SQLite file; `memory` keeps nothing, which is what a conformance run wants. */
export const storageLocation = () => withDefault('OIDCRAFT_DB', 'data/oidcraft.sqlite')

export const openStorage = async (options: StorageOptions): Promise<Adapter> => {
  const location = storageLocation()
  if (location !== 'memory') console.log(`[oidcraft] storing in ${location}`)
  return openAdapter(location, options)
}
