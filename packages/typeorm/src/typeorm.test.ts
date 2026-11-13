import { describe, expect, test } from 'bun:test'
import { generatedKeyStore } from '@oidcraft/adapter'
import { adapterConformance } from '@oidcraft/adapter/conformance'
import { DataSource, type DataSourceOptions } from 'typeorm'
import { OIDCRAFT_SQLITE_ENTITIES, TYPEORM_SQLITE_MIGRATIONS, typeormAdapter } from './index'

const accounts = {
  async find(accountId: string) {
    return { accountId, claims: {} }
  },
  async claims() {
    return {}
  }
}

const fresh = async (options: Pick<DataSourceOptions, 'invalidWhereValuesBehavior'> = {}) => {
  const dataSource = new DataSource({
    type: 'sqljs',
    entities: OIDCRAFT_SQLITE_ENTITIES,
    migrations: TYPEORM_SQLITE_MIGRATIONS,
    ...options
  })
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
  test('the entities describe exactly the tables the migrations made', async () => {
    const { dataSource } = await fresh()
    expect((await dataSource.driver.createSchemaBuilder().log()).upQueries.map(query => query.query)).toEqual([])
  })

  test('a missing value is refused, not dropped, under a host that ignores undefined in a where', async () => {
    const { adapter } = await fresh({ invalidWhereValuesBehavior: { undefined: 'ignore', null: 'ignore' } })
    const identities = adapter.identities as NonNullable<typeof adapter.identities>
    await identities.upsert({ accountId: 'u1', provider: 'google', subject: 'g-1', claims: {}, linkedAt: new Date() })
    await expect(identities.find('google', undefined as never)).rejects.toThrow(/subject/)
    await expect(identities.destroy('google', undefined as never)).rejects.toThrow(/subject/)
    await expect(adapter.grants.find(null as never)).rejects.toThrow(/id/)
    expect((await identities.find('google', 'g-1'))?.accountId).toBe('u1')
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
