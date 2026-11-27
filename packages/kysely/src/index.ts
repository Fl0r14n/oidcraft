import type { AccountStore, FullAdapter, KeyStore } from '@oidcraft/adapter'
import { type Dialect, type Execute, sqlAdapter, type Table } from '@oidcraft/sql/store'
import { type Kysely, MysqlAdapter, PostgresAdapter, sql } from 'kysely'
import type { OidcraftDatabase } from './schema'

export type KyselyAdapterOptions = {
  /** On SQLite, Postgres, or MySQL and MariaDB through `MysqlDialect`, each over its own migrations (FR-A4). */
  db: Kysely<OidcraftDatabase>
  keys: KeyStore
  /** Omitted, every account lookup misses: the host composes one in later, as `@oidcraft/provider/accounts` does. */
  accounts?: AccountStore
}

const dialectOf = (db: Kysely<OidcraftDatabase>): Dialect => {
  const { adapter } = db.getExecutor()
  if (adapter instanceof MysqlAdapter) return 'mysql'
  return adapter instanceof PostgresAdapter ? 'postgres' : 'sqlite'
}

/** The shared stores over Kysely, which runs each statement as a raw one. */
export const kyselyAdapter = ({ db, keys, accounts }: KyselyAdapterOptions): FullAdapter => {
  // G-6: a raw statement escapes `withSchema`, so each table is named as a compiled select names it, the host's plugins applied.
  const names = new Map<Table, ReturnType<typeof sql.raw>>()
  const named = (table: Table) => {
    let name = names.get(table)
    if (!name) {
      name = sql.raw(
        db
          .selectFrom(table)
          .selectAll()
          .compile()
          .sql.replace(/^select \* from /, '')
      )
      names.set(table, name)
    }
    return name
  }
  const execute: Execute = async ({ strings, slots }) => {
    const parts = slots.map(slot => ('table' in slot ? named(slot.table) : slot.value))
    const result = await sql<Record<string, unknown>>(strings as unknown as TemplateStringsArray, ...parts).execute(db)
    return { rows: result.rows, affected: Number(result.numAffectedRows ?? 0) }
  }
  return sqlAdapter({ dialect: dialectOf(db), execute, keys, accounts })
}

export { MYSQL_MIGRATIONS } from '@oidcraft/sql/mysql'
export { POSTGRES_MIGRATIONS } from '@oidcraft/sql/postgres'
export { type Migration, SQLITE_MIGRATIONS } from '@oidcraft/sql/sqlite'
export type { OidcraftDatabase } from './schema'
export * from './schema'
