import { describe, expect, test } from 'bun:test'
import { generatedKeyStore } from '@oidcraft/adapter'
import { adapterConformance } from '@oidcraft/adapter/conformance'
import { DataSource } from 'typeorm'
import { OIDCRAFT_SQLITE_ENTITIES, TYPEORM_SQLITE_MIGRATIONS, typeormAdapter } from './index'

const accounts = {
  async find(accountId: string) {
    return { accountId, claims: {} }
  },
  async claims() {
    return {}
  }
}

const fresh = async () => {
  const dataSource = new DataSource({ type: 'sqljs', entities: OIDCRAFT_SQLITE_ENTITIES, migrations: TYPEORM_SQLITE_MIGRATIONS })
  await dataSource.initialize()
  await dataSource.runMigrations()
  return { dataSource, adapter: typeormAdapter({ dataSource, keys: await generatedKeyStore(), accounts }) }
}

describe('typeorm adapter', () => {
  // The identical suite the memory, Drizzle and Kysely adapters run (FR-A6).
  for (const check of adapterConformance(async () => (await fresh()).adapter, { implements: ['identities', 'credentials', 'realms'] })) {
    test(`typeorm/sqlite: ${check.name}`, check.run)
  }

  test('the shipped migrations run through TypeORM, in order, once', async () => {
    const { dataSource } = await fresh()
    expect((await dataSource.query('select name from migrations order by id')).map((row: { name: string }) => row.name)).toEqual(
      TYPEORM_SQLITE_MIGRATIONS.map(migration => migration.name)
    )
    expect(await dataSource.runMigrations()).toEqual([])
  })

  // FR-A4: entities that disagree with the migrations make TypeORM's schema builder rebuild every table.
  // FR-A4: entities that disagree with the migrations would have TypeORM's schema builder rebuild tables.
  test('the entities describe exactly the tables the migrations made', async () => {
    const { dataSource } = await fresh()
    expect((await dataSource.driver.createSchemaBuilder().log()).upQueries.map(query => query.query)).toEqual([])
  })

  test('revocation uses the grant index rather than scanning', async () => {
    const { dataSource } = await fresh()
    const plan: { detail: string }[] = await dataSource.query("explain query plan delete from oidc_artifacts where grant_id = 'g1'")
    expect(plan.map(row => row.detail).join(' ')).toContain('oidc_artifacts_grant_idx')
  })

  test('a DataSource without the entities is refused at construction', async () => {
    const bare = new DataSource({ type: 'sqljs', entities: [] })
    await bare.initialize()
    expect(() => typeormAdapter({ dataSource: bare, keys: { active: async () => [] } as never })).toThrow(/OIDCRAFT_SQLITE_ENTITIES/)
  })
})
