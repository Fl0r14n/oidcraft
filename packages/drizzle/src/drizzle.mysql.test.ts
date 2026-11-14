import { afterAll, describe, expect, test } from 'bun:test'
import { generatedKeyStore } from '@oidcraft/adapter'
import { adapterConformance } from '@oidcraft/adapter/conformance'
import { DROP_TIMEOUT, dropDatabases, freshDatabase, MYSQL_SERVERS, migrateDatabase } from '@oidcraft/sql/testing/mysql'
import { drizzle } from 'drizzle-orm/mysql2'
import { createPool } from 'mysql2/promise'
import { drizzleAdapter, mysqlTables } from './index'

const accounts = {
  async find(accountId: string) {
    return { accountId, claims: {} }
  },
  async claims() {
    return {}
  }
}

const dbOf = (uri: string, flags?: string) =>
  drizzle({ client: createPool({ uri, connectionLimit: 4, maxIdle: 0, idleTimeout: 200, ...(flags && { flags: [flags] }) }) })

afterAll(dropDatabases, DROP_TIMEOUT)

for (const server of MYSQL_SERVERS) {
  describe.skipIf(!server.url)(`drizzle adapter on ${server.name}`, () => {
    const url = server.url as string
    const adapterIn = async () =>
      drizzleAdapter({
        db: dbOf((await freshDatabase(url)).uri, server.flags),
        tables: mysqlTables(),
        keys: await generatedKeyStore(),
        accounts
      })

    // The identical suite every adapter runs, on the shipped MySQL schema (FR-A4).
    for (const check of adapterConformance(adapterIn, { implements: ['identities', 'credentials', 'passkeys', 'realms'] })) {
      test(`drizzle/${server.name}: ${check.name}`, check.run)
    }

    // NFR-S5: a client chooses its jti's length; the key it is stored under has a fixed one.
    test('a replay value of any length is claimed once', async () => {
      const adapter = await adapterIn()
      const jti = 'x'.repeat(5_000)
      expect(await adapter.replay.claim('dpop', jti, 60)).toBe(true)
      expect(await adapter.replay.claim('dpop', jti, 60)).toBe(false)
    })

    // G-6: a realm is a database of its own on one server, chosen by the host's configure.
    test('two databases on one server share nothing', async () => {
      const { name, uri } = await freshDatabase(url)
      const other = `${name}_other`
      await migrateDatabase(url, other)
      const db = dbOf(uri)
      const keys = await generatedKeyStore()
      const acme = drizzleAdapter({ db, tables: mysqlTables(), keys, accounts })
      const globex = drizzleAdapter({ db, tables: mysqlTables(other), keys, accounts })
      await acme.clients.upsert?.({
        clientId: 'rp',
        redirectUris: ['https://rp.example.com/cb'],
        grantTypes: ['authorization_code'],
        responseTypes: ['code'],
        scopes: ['openid'],
        tokenEndpointAuthMethod: 'none',
        createdAt: new Date(),
        updatedAt: new Date()
      })
      expect(await acme.clients.find('rp')).toBeTruthy()
      expect(await globex.clients.find('rp')).toBeUndefined()
    })
  })
}
