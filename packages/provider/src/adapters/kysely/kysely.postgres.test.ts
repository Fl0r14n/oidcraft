import { afterAll, describe, expect, test } from 'bun:test'
import { Kysely, PostgresDialect } from 'kysely'
import { generatedKeyStore } from '../../keys/keys'
import { adapterConformance } from '../conformance'
import { dropSchemas, freshSchema, migrateSchema, POSTGRES_URL } from '../postgres-testing'
import { kyselyAdapter, type OidcraftDatabase } from './index'

const accounts = {
  async find(accountId: string) {
    return { accountId, claims: {} }
  },
  async claims() {
    return {}
  }
}

const adapterIn = async () => {
  const { pool } = await freshSchema()
  return kyselyAdapter({
    db: new Kysely<OidcraftDatabase>({ dialect: new PostgresDialect({ pool }) }),
    keys: await generatedKeyStore(),
    accounts
  })
}

describe.skipIf(!POSTGRES_URL)('kysely adapter on Postgres', () => {
  afterAll(dropSchemas)

  // The identical suite every adapter runs, on the shipped Postgres schema (FR-A4).
  adapterConformance('kysely/postgres', adapterIn)

  // G-6: a realm is a schema of its own in one database, chosen by the host's configure.
  test('two schemas in one database share nothing', async () => {
    const { pool } = await freshSchema()
    const other = `${(await pool.query('select current_schema() as name')).rows[0].name}_other`
    await migrateSchema(other)
    const db = new Kysely<OidcraftDatabase>({ dialect: new PostgresDialect({ pool }) })
    const keys = await generatedKeyStore()
    const acme = kyselyAdapter({ db, keys, accounts })
    const globex = kyselyAdapter({ db: db.withSchema(other), keys, accounts })
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
