import { afterAll, describe, expect, test } from 'bun:test'
/// <reference types="bun" />
import { SQL } from 'bun'
import { drizzle as drizzleBun } from 'drizzle-orm/bun-sql'
import { drizzle } from 'drizzle-orm/node-postgres'
import { generatedKeyStore } from '../../keys/keys'
import { adapterConformance } from '../conformance'
import { dropSchemas, freshSchema, migrateSchema, POSTGRES_URL } from '../postgres-testing'
import { drizzleAdapter, postgresTables } from './index'

const accounts = {
  async find(accountId: string) {
    return { accountId, claims: {} }
  },
  async claims() {
    return {}
  }
}

describe.skipIf(!POSTGRES_URL)('drizzle adapter on Postgres', () => {
  afterAll(dropSchemas)

  // The identical suite every adapter runs, on the shipped Postgres schema (FR-A4).
  adapterConformance('drizzle/postgres', async () => {
    const { pool } = await freshSchema()
    return drizzleAdapter({ db: drizzle({ client: pool }), tables: postgresTables(), keys: await generatedKeyStore(), accounts })
  })

  // G-6: postgresTables(schema) is how a realm's adapter is pointed at its own schema.
  test('two schemas in one database share nothing', async () => {
    const { pool, name } = await freshSchema()
    const other = `${name}_other`
    await migrateSchema(other)
    const db = drizzle({ client: pool })
    const keys = await generatedKeyStore()
    const acme = drizzleAdapter({ db, tables: postgresTables(name), keys, accounts })
    const globex = drizzleAdapter({ db, tables: postgresTables(other), keys, accounts })
    const client = {
      clientId: 'rp',
      redirectUris: ['https://rp.example.com/cb'],
      grantTypes: ['authorization_code'],
      responseTypes: ['code'],
      scopes: ['openid'],
      tokenEndpointAuthMethod: 'none' as const,
      createdAt: new Date(),
      updatedAt: new Date()
    }
    await acme.clients.upsert?.(client)
    expect(await acme.clients.find('rp')).toBeTruthy()
    expect(await globex.clients.find('rp')).toBeUndefined()
  })
})

// Bun's own driver, which a Bun host would reach for first. It too reads bigint back as a string.
describe.skipIf(!POSTGRES_URL)('drizzle adapter on Postgres through Bun.sql', () => {
  const sql = POSTGRES_URL ? new SQL(POSTGRES_URL) : undefined
  afterAll(async () => {
    await sql?.close()
    await dropSchemas()
  })

  adapterConformance('drizzle/bun-sql', async () => {
    const { name } = await freshSchema()
    return drizzleAdapter({
      db: drizzleBun({ client: sql as SQL }),
      tables: postgresTables(name),
      keys: await generatedKeyStore(),
      accounts
    })
  })
})
