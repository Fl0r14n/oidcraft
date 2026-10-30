import { afterAll, describe, expect, test } from 'bun:test'
import { DataSource } from 'typeorm'
import { generatedKeyStore } from '../../keys/keys'
import { adapterConformance } from '../conformance'
import { dropSchemas, emptySchema, POSTGRES_URL } from '../postgres-testing'
import { OIDCRAFT_ENTITIES, TYPEORM_POSTGRES_MIGRATIONS, typeormAdapter } from './index'

const accounts = {
  async find(accountId: string) {
    return { accountId, claims: {} }
  },
  async claims() {
    return {}
  }
}

const sources: DataSource[] = []

// A schema of its own per test, migrated by TypeORM itself, so the shipped classes are what is tested.
const fresh = async () => {
  const schema = await emptySchema()
  const dataSource = new DataSource({
    type: 'postgres',
    url: POSTGRES_URL as string,
    schema,
    entities: OIDCRAFT_ENTITIES,
    migrations: TYPEORM_POSTGRES_MIGRATIONS,
    extra: { max: 2, options: `-c search_path=${schema}` }
  })
  await dataSource.initialize()
  sources.push(dataSource)
  await dataSource.runMigrations()
  return { dataSource, adapter: typeormAdapter({ dataSource, keys: await generatedKeyStore(), accounts }) }
}

describe.skipIf(!POSTGRES_URL)('typeorm adapter on Postgres', () => {
  afterAll(async () => {
    for (const source of sources.splice(0)) await source.destroy()
    await dropSchemas()
  })

  // The identical suite every adapter runs (FR-A4, FR-A6).
  adapterConformance('typeorm/postgres', async () => (await fresh()).adapter)

  test('the shipped migrations run through TypeORM, in order, once', async () => {
    const { dataSource } = await fresh()
    expect((await dataSource.query('select name from migrations order by id')).map((row: { name: string }) => row.name)).toEqual(
      TYPEORM_POSTGRES_MIGRATIONS.map(migration => migration.name)
    )
    expect(await dataSource.runMigrations()).toEqual([])
  })
})
