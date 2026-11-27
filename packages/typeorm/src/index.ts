import type { AccountStore, FullAdapter, KeyStore } from '@oidcraft/adapter'
import { type Dialect, type Execute, sqlAdapter, type Table } from '@oidcraft/sql/store'
import type { DataSource } from 'typeorm'
import { OIDCRAFT_TABLES } from './schema'

export type TypeormAdapterOptions = {
  /** Initialized, with `OIDCRAFT_SQLITE_ENTITIES`, `OIDCRAFT_POSTGRES_ENTITIES` or `OIDCRAFT_MYSQL_ENTITIES` among its entities and the migrations already run. */
  dataSource: DataSource
  keys: KeyStore
  /** Omitted, every account lookup misses: the host composes one in later, as `@oidcraft/provider/accounts` does. */
  accounts?: AccountStore
}

const dialectOf = (dataSource: DataSource): Dialect => {
  const { type } = dataSource.driver.options
  if (type === 'mysql' || type === 'mariadb') return 'mysql'
  return type === 'postgres' ? 'postgres' : 'sqlite'
}

/** The shared stores over the host's TypeORM `DataSource` (FR-A6), each table named as its entity is, schema included (G-6). */
export const typeormAdapter = ({ dataSource, keys, accounts }: TypeormAdapterOptions): FullAdapter => {
  const missing = OIDCRAFT_TABLES.filter(table => !dataSource.hasMetadata(table))
  if (missing.length) {
    throw new Error(
      `the DataSource does not know ${missing.join(', ')}: add OIDCRAFT_SQLITE_ENTITIES, OIDCRAFT_POSTGRES_ENTITIES or OIDCRAFT_MYSQL_ENTITIES to its entities`
    )
  }
  const dialect = dialectOf(dataSource)
  const { driver } = dataSource
  const named = (table: Table) =>
    dataSource
      .getMetadata(table)
      .tablePath.split('.')
      .map(part => driver.escape(part))
      .join('.')

  const execute: Execute = async ({ strings, slots }) => {
    const params: unknown[] = []
    let text = strings[0] as string
    slots.forEach((slot, index) => {
      if ('table' in slot) text += named(slot.table)
      else {
        params.push(slot.value)
        text += dialect === 'postgres' ? `$${params.length}` : '?'
      }
      text += strings[index + 1]
    })
    const runner = dataSource.createQueryRunner()
    try {
      const result = await runner.query(text, params, true)
      return { rows: Array.isArray(result.records) ? result.records : [], affected: result.affected ?? 0 }
    } finally {
      await runner.release()
    }
  }
  return sqlAdapter({ dialect, execute, keys, accounts })
}

export { MYSQL_MIGRATIONS } from '@oidcraft/sql/mysql'
export { POSTGRES_MIGRATIONS } from '@oidcraft/sql/postgres'
export { type Migration, SQLITE_MIGRATIONS } from '@oidcraft/sql/sqlite'
export * from './schema'
