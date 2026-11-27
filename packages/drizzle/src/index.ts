import type { AccountStore, FullAdapter, KeyStore } from '@oidcraft/adapter'
import { type Dialect, type Execute, sqlAdapter } from '@oidcraft/sql/store'
import { type AnyRelations, getTableName, is, type SQL, sql, type Table } from 'drizzle-orm'
import { MySqlTable } from 'drizzle-orm/mysql-core'
import type { PgQueryResultHKT } from 'drizzle-orm/pg-core'
import { PgTable } from 'drizzle-orm/pg-core'
import type { PgAsyncDatabase } from 'drizzle-orm/pg-core/async'
import type { SQLiteAsyncDatabase } from 'drizzle-orm/sqlite-core'
import type { MysqlTables } from './mysql-schema'
import type { PostgresTables } from './postgres-schema'
import { schema } from './schema'

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

type Runs = {
  all(query: SQL): Promise<Record<string, unknown>[]>
  run(query: SQL): Promise<unknown>
  execute(query: SQL): Promise<unknown>
}

// better-sqlite3 throws when `all` runs a statement that returns nothing, where bun:sqlite answers []: each goes to its own call.
const returnsRows = (strings: readonly string[]) => {
  const text = strings.join(' ').trimStart().toLowerCase()
  return text.startsWith('select') || text.startsWith('with') || /\breturning\b/.test(text)
}

/** node-postgres answers a result with `rows`, postgres.js the rows themselves; mysql2 a pair whose first is rows or a header. */
const executed = (dialect: Dialect, result: unknown) => {
  if (dialect === 'postgres')
    return { rows: (Array.isArray(result) ? result : (result as { rows: Record<string, unknown>[] }).rows) ?? [], affected: 0 }
  const [first] = result as [Record<string, unknown>[] | { affectedRows?: number }]
  return Array.isArray(first) ? { rows: first, affected: 0 } : { rows: [], affected: first?.affectedRows ?? 0 }
}

/** The shared stores over Drizzle. A table is the host's table object, so the schema or database it was built in is the one used (G-6). */
export const drizzleAdapter = (options: DrizzleAdapterOptions): FullAdapter => {
  const db = options.db as Runs
  const tables = (options.tables ?? schema) as Record<string, Table>
  const byName = new Map(Object.values(tables).map(table => [getTableName(table), table]))
  const dialect: Dialect = is(tables.clients, MySqlTable) ? 'mysql' : is(tables.clients, PgTable) ? 'postgres' : 'sqlite'

  const execute: Execute = async ({ strings, slots }) => {
    const parts = slots.map(slot => ('table' in slot ? byName.get(slot.table) : slot.value))
    const query = sql(strings as unknown as TemplateStringsArray, ...(parts as never[]))
    if (dialect === 'sqlite') {
      if (returnsRows(strings)) return { rows: await db.all(query), affected: 0 }
      await db.run(query)
      return { rows: [], affected: 0 }
    }
    return executed(dialect, await db.execute(query))
  }
  return sqlAdapter({ dialect, execute, keys: options.keys, accounts: options.accounts })
}

export { MYSQL_MIGRATIONS } from '@oidcraft/sql/mysql'
export { POSTGRES_MIGRATIONS } from '@oidcraft/sql/postgres'
export { type Migration, SQLITE_MIGRATIONS } from '@oidcraft/sql/sqlite'
export { type MysqlTables, mysqlTables } from './mysql-schema'
export { type PostgresTables, postgresTables } from './postgres-schema'
export * from './schema'
export { schema } from './schema'
