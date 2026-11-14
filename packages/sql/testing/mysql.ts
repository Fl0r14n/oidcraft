/// <reference types="bun" />
import mysql from 'mysql2/promise'
import { MYSQL_MIGRATIONS } from '../src/mysql'

/**
 * One dialect, held to two servers; CI runs both, and without a URL its suite skips, as the Postgres ones do. mysql2
 * counts matched rows as affected by default and a host may turn that off, so one server runs each way: the count
 * is the client's choice, not the server's.
 */
export const MYSQL_SERVERS = [
  { name: 'mysql', url: Bun.env.MYSQL_URL, flags: undefined },
  { name: 'mariadb', url: Bun.env.MARIADB_URL, flags: '-FOUND_ROWS' }
] as const

/** Dropping a database per test takes longer than a hook's default 5 seconds. */
export const DROP_TIMEOUT = 120_000

const created: { url: string; name: string }[] = []

const withConnection = async <T>(url: string, run: (connection: mysql.Connection) => Promise<T>) => {
  const connection = await mysql.createConnection(url)
  try {
    return await run(connection)
  } finally {
    await connection.end()
  }
}

const nextName = () => `oidcraft_test_${process.pid}_${created.length}_${Date.now()}`

/** An empty database, for a test that applies the migrations through its own tooling. */
export const emptyDatabase = async (url: string) => {
  const name = nextName()
  await withConnection(url, connection => connection.query(`create database ${name}`))
  created.push({ url, name })
  return name
}

/** Migrates MYSQL_MIGRATIONS into the named database, which is MySQL's schema: a realm's own (G-6). */
export const migrateDatabase = (url: string, name: string) =>
  withConnection(url, async connection => {
    await connection.query(`create database ${name}`)
    created.push({ url, name })
    await connection.query(`use ${name}`)
    for (const statement of MYSQL_MIGRATIONS.flatMap(migration => migration.statements)) await connection.query(statement)
  })

/** The server's URL with the named database, for a pool of the test's own driver flavour. */
export const databaseUrl = (url: string, name: string) => {
  const target = new URL(url)
  target.pathname = `/${name}`
  return target.toString()
}

/** A migrated database of its own per test, so no test sees another's rows. */
export const freshDatabase = async (url: string) => {
  const name = nextName()
  await migrateDatabase(url, name)
  return { name, uri: databaseUrl(url, name) }
}

export const dropDatabases = async () => {
  for (const { url, name } of created.splice(0))
    await withConnection(url, connection => connection.query(`drop database if exists ${name}`))
}
