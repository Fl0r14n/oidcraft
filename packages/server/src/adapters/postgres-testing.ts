/// <reference types="bun" />
import pg from 'pg'
import { POSTGRES_MIGRATIONS } from './sql/postgres'

/** Set in CI, which runs a Postgres service. Without it the Postgres suites skip, as Redis's do. */
export const POSTGRES_URL = Bun.env.POSTGRES_URL

const created: string[] = []

const withClient = async <T>(run: (client: pg.Client) => Promise<T>) => {
  const client = new pg.Client({ connectionString: POSTGRES_URL })
  await client.connect()
  try {
    return await run(client)
  } finally {
    await client.end()
  }
}

/** An empty schema, for a test that applies the migrations through its own tooling. */
export const emptySchema = async () => {
  const name = `oidcraft_test_${process.pid}_${created.length}_${Date.now()}`
  await withClient(client => client.query(`create schema ${name}`))
  created.push(name)
  return name
}

/** Migrates POSTGRES_MIGRATIONS into the named schema, the way a host provisions a realm (G-6). */
export const migrateSchema = (name: string) =>
  withClient(async client => {
    await client.query(`create schema ${name}`)
    await client.query(`set search_path to ${name}`)
    for (const statement of POSTGRES_MIGRATIONS.flatMap(migration => migration.statements)) await client.query(statement)
    created.push(name)
  })

/** A schema of its own per test, so no test sees another's rows; and a pool whose connections live in it. */
export const freshSchema = async () => {
  const name = `oidcraft_test_${process.pid}_${created.length}_${Date.now()}`
  await migrateSchema(name)
  const pool = new pg.Pool({ connectionString: POSTGRES_URL, max: 2, idleTimeoutMillis: 200, options: `-c search_path=${name}` })
  return { name, pool }
}

export const dropSchemas = () =>
  withClient(async client => {
    for (const name of created.splice(0)) await client.query(`drop schema if exists ${name} cascade`)
  })
