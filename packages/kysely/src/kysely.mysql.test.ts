import { afterAll, describe, expect, test } from 'bun:test'
import { generatedKeyStore } from '@oidcraft/adapter'
import { adapterConformance } from '@oidcraft/adapter/conformance'
import { DROP_TIMEOUT, dropDatabases, freshDatabase, MYSQL_SERVERS, migrateDatabase } from '@oidcraft/sql/testing/mysql'
import { Kysely, MysqlDialect } from 'kysely'
import { createPool } from 'mysql2'
import { kyselyAdapter, type OidcraftDatabase } from './index'

const accounts = {
  async find(accountId: string) {
    return { accountId, claims: {} }
  },
  async claims() {
    return {}
  }
}

const dbOf = (uri: string, flags?: string) =>
  new Kysely<OidcraftDatabase>({
    dialect: new MysqlDialect({
      pool: createPool({ uri, connectionLimit: 4, maxIdle: 0, idleTimeout: 200, ...(flags && { flags: [flags] }) })
    })
  })

afterAll(dropDatabases, DROP_TIMEOUT)

for (const server of MYSQL_SERVERS) {
  describe.skipIf(!server.url)(`kysely adapter on ${server.name}`, () => {
    const url = server.url as string
    const adapterIn = async () =>
      kyselyAdapter({ db: dbOf((await freshDatabase(url)).uri, server.flags), keys: await generatedKeyStore(), accounts })

    for (const check of adapterConformance(adapterIn, { implements: ['identities', 'credentials', 'passkeys', 'realms'] })) {
      test(`kysely/${server.name}: ${check.name}`, check.run)
    }

    // NFR-S5: a client chooses its jti's length; the key it is stored under has a fixed one.
    test('a replay value of any length is claimed once', async () => {
      const adapter = kyselyAdapter({ db: dbOf((await freshDatabase(url)).uri), keys: await generatedKeyStore(), accounts })
      const jti = 'x'.repeat(5_000)
      expect(await adapter.replay.claim('dpop', jti, 60)).toBe(true)
      expect(await adapter.replay.claim('dpop', jti, 60)).toBe(false)
      expect(await adapter.replay.claim('dpop', `${jti}y`, 60)).toBe(true)
    })

    // Ids are case-sensitive; MySQL's default collations are not.
    test('ids that differ only in case are two records', async () => {
      const adapter = kyselyAdapter({ db: dbOf((await freshDatabase(url)).uri), keys: await generatedKeyStore(), accounts })
      const expiresAt = new Date(Date.now() + 60_000)
      await adapter.artifacts.upsert({ id: 'AbC', kind: 'access_token', clientId: 'c', payload: {}, expiresAt })
      expect(await adapter.artifacts.find('access_token', 'abc')).toBeUndefined()
      expect(await adapter.replay.claim('n', 'Token', 60)).toBe(true)
      expect(await adapter.replay.claim('n', 'token', 60)).toBe(true)
    })

    // FR-I8: a credential id may be 1023 bytes, which is 1364 characters of base64url.
    test('a passkey with the longest credential id WebAuthn allows is stored', async () => {
      const adapter = kyselyAdapter({ db: dbOf((await freshDatabase(url)).uri), keys: await generatedKeyStore(), accounts })
      const credentialId = 'A'.repeat(1364)
      const passkey = {
        credentialId,
        accountId: 'a1',
        publicKey: 'k',
        algorithm: -7,
        counter: 0,
        transports: [],
        name: 'Key',
        createdAt: new Date()
      }
      expect(await adapter.passkeys.create(passkey)).toBe(true)
      expect((await adapter.passkeys.find(credentialId))?.accountId).toBe('a1')
    })

    // G-6: a realm is a database of its own on one server, reached through withSchema.
    test('two databases on one server share nothing', async () => {
      const { name, uri } = await freshDatabase(url)
      const other = `${name}_other`
      await migrateDatabase(url, other)
      const db = dbOf(uri)
      const keys = await generatedKeyStore()
      const acme = kyselyAdapter({ db, keys, accounts })
      const globex = kyselyAdapter({ db: db.withSchema(other), keys, accounts })
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
