/// <reference types="bun" />

import { Database } from 'bun:sqlite'
import { describe, expect, test } from 'bun:test'
import { Kysely, sql } from 'kysely'
import { BunSqliteDialect } from 'kysely-bun-sqlite'
import { generatedKeyStore } from '../../keys/keys'
import { adapterConformance } from '../conformance'
import { SQLITE_MIGRATIONS } from '../sql/sqlite'
import { kyselyAdapter, type OidcraftDatabase } from './index'

const accounts = {
  async find(accountId: string) {
    return { accountId, claims: {} }
  },
  async claims() {
    return {}
  }
}

const fresh = async () => {
  const sqlite = new Database(':memory:')
  for (const statement of SQLITE_MIGRATIONS.flatMap(migration => migration.statements)) sqlite.run(statement)
  const db = new Kysely<OidcraftDatabase>({ dialect: new BunSqliteDialect({ database: sqlite }) })
  return { db, adapter: kyselyAdapter({ db, keys: await generatedKeyStore(), accounts }) }
}

describe('kysely adapter', () => {
  // The identical suite the memory and Drizzle adapters run (FR-A4).
  adapterConformance('kysely/sqlite', async () => (await fresh()).adapter)

  test('revocation uses the grant index rather than scanning', async () => {
    const { db } = await fresh()
    const plan = await sql<{ detail: string }>`explain query plan delete from oidc_artifacts where grant_id = 'g1'`.execute(db)
    expect(plan.rows.map(row => row.detail).join(' ')).toContain('oidc_artifacts_grant_idx')
  })

  test('prune removes expired rows and reports how many', async () => {
    const { adapter } = await fresh()
    await adapter.artifacts.upsert({ id: 'old', kind: 'access_token', clientId: 'c1', payload: {}, expiresAt: new Date(Date.now() - 1000) })
    await adapter.artifacts.upsert({
      id: 'new',
      kind: 'access_token',
      clientId: 'c1',
      payload: {},
      expiresAt: new Date(Date.now() + 60_000)
    })
    expect(await adapter.artifacts.prune?.(new Date(), 100)).toBe(1)
    expect((await adapter.artifacts.find('access_token', 'new'))?.id).toBe('new')
  })
})
