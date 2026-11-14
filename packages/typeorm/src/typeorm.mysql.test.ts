import { afterAll, describe, expect, test } from 'bun:test'
import { generatedKeyStore } from '@oidcraft/adapter'
import { adapterConformance } from '@oidcraft/adapter/conformance'
import { DROP_TIMEOUT, databaseUrl, dropDatabases, emptyDatabase, MYSQL_SERVERS } from '@oidcraft/sql/testing/mysql'
import { DataSource } from 'typeorm'
import { OIDCRAFT_MYSQL_ENTITIES, TYPEORM_MYSQL_MIGRATIONS, typeormAdapter } from './index'

const accounts = {
  async find(accountId: string) {
    return { accountId, claims: {} }
  },
  async claims() {
    return {}
  }
}

const sources: DataSource[] = []

afterAll(async () => {
  for (const source of sources.splice(0)) await source.destroy()
  await dropDatabases()
}, DROP_TIMEOUT)

for (const server of MYSQL_SERVERS) {
  describe.skipIf(!server.url)(`typeorm adapter on ${server.name}`, () => {
    const url = server.url as string

    // A database of its own per test, migrated by TypeORM itself, so the shipped classes are what is tested.
    const fresh = async () => {
      const database = await emptyDatabase(url)
      const dataSource = new DataSource({
        type: server.name,
        // TypeORM takes the database from the URL over `database`.
        url: databaseUrl(url, database),
        entities: OIDCRAFT_MYSQL_ENTITIES,
        migrations: TYPEORM_MYSQL_MIGRATIONS,
        poolSize: 4,
        ...(server.flags && { flags: [server.flags] })
      })
      await dataSource.initialize()
      sources.push(dataSource)
      await dataSource.runMigrations()
      return { dataSource, adapter: typeormAdapter({ dataSource, keys: await generatedKeyStore(), accounts }) }
    }

    for (const check of adapterConformance(async () => (await fresh()).adapter, {
      implements: ['identities', 'credentials', 'passkeys', 'realms']
    })) {
      test(`typeorm/${server.name}: ${check.name}`, check.run)
    }

    // FR-A4: entities that disagree with the migrations would have TypeORM's schema builder rebuild tables.
    test('the entities describe exactly the tables the migrations made', async () => {
      const { dataSource } = await fresh()
      expect((await dataSource.driver.createSchemaBuilder().log()).upQueries.map(query => query.query)).toEqual([])
    })

    test('the shipped migrations run through TypeORM, in order, once', async () => {
      const { dataSource } = await fresh()
      expect((await dataSource.query('select name from migrations order by id')).map((row: { name: string }) => row.name)).toEqual(
        TYPEORM_MYSQL_MIGRATIONS.map(migration => migration.name)
      )
      expect(await dataSource.runMigrations()).toEqual([])
    })

    // NFR-S5: a client chooses its jti's length; the key it is stored under has a fixed one.
    test('a replay value of any length is claimed once', async () => {
      const { adapter } = await fresh()
      const jti = 'x'.repeat(5_000)
      expect(await adapter.replay.claim('dpop', jti, 60)).toBe(true)
      expect(await adapter.replay.claim('dpop', jti, 60)).toBe(false)
    })
  })
}
