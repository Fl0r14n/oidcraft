/// <reference types="bun" />

import { Database } from 'bun:sqlite'
import { describe, expect, test } from 'bun:test'
import { sql } from 'drizzle-orm'
import { drizzle } from 'drizzle-orm/bun-sqlite'
import { generatedKeyStore } from '../../keys/keys'
import { adapterConformance } from '../conformance'
import { SQLITE_MIGRATIONS } from '../sql/sqlite'
import { type DrizzleDatabase, drizzleAdapter } from './index'

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
  const db: DrizzleDatabase = drizzle({ client: sqlite })
  return { db, adapter: drizzleAdapter({ db, keys: await generatedKeyStore(), accounts }) }
}

describe('drizzle adapter', () => {
  // The same suite the memory adapter runs: passing both is what "interchangeable" means (FR-A4).
  adapterConformance('drizzle/sqlite', async () => (await fresh()).adapter)

  // FR-A5: the criticism of the blob-table shape only holds if this adapter avoids it.
  test('revocation is an indexed delete, not a scan', async () => {
    const { db } = await fresh()
    const plan = await db.all<{ detail: string }>(sql`explain query plan delete from oidc_artifacts where grant_id = 'g1'`)
    expect(plan.map(row => row.detail).join(' ')).toContain('oidc_artifacts_grant_idx')
  })

  test('the user-code lookup uses its index', async () => {
    const { db } = await fresh()
    const plan = (db as unknown as { all: (q: unknown) => { detail: string }[] }).all(
      sql`explain query plan select * from oidc_artifacts where user_code = 'WDJB-MJHT'`
    )
    expect(plan.map(row => row.detail).join(' ')).toContain('oidc_artifacts_user_code_idx')
  })

  test('an artifact is stored in real columns, not one JSON blob', async () => {
    const { db, adapter } = await fresh()
    await adapter.artifacts.upsert({
      id: 'a1',
      kind: 'refresh_token',
      clientId: 'c1',
      accountId: 'u1',
      grantId: 'g1',
      payload: { scopes: ['openid'] },
      expiresAt: new Date(Date.now() + 60_000)
    })
    const [row] = (db as unknown as { all: (q: unknown) => Record<string, unknown>[] }).all(
      sql`select client_id, account_id, grant_id from oidc_artifacts where id = 'a1'`
    )
    expect(row).toEqual({ client_id: 'c1', account_id: 'u1', grant_id: 'g1' })
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

  test('one grant per account and client, enforced by the database', async () => {
    const { adapter } = await fresh()
    const base = { accountId: 'u1', clientId: 'c1', scopes: ['openid'], claims: [], resources: {}, createdAt: new Date() }
    await adapter.grants.upsert({ id: 'g1', ...base })
    expect(adapter.grants.upsert({ id: 'g2', ...base })).rejects.toThrow()
  })
})
