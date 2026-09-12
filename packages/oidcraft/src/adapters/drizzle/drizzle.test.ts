/// <reference types="bun" />

import { Database } from 'bun:sqlite'
import { describe, expect, test } from 'bun:test'
import { sql } from 'drizzle-orm'
import { drizzle } from 'drizzle-orm/bun-sqlite'
import { adapterConformance } from '../../adapter-conformance'
import { generatedKeyStore } from '../../keys'
import { type DrizzleDatabase, drizzleAdapter } from './index'

/** The schema the adapter owns. A deployment runs this as a migration; the library never applies it. */
const MIGRATION = `
create table oidc_clients (client_id text primary key, data text not null, created_at integer not null, updated_at integer not null);
create table oidc_artifacts (kind text not null, id text not null, client_id text not null, account_id text,
  grant_id text, user_code text, payload text not null, consumed_at integer, expires_at integer not null,
  primary key (kind, id));
create index oidc_artifacts_grant_idx on oidc_artifacts (grant_id);
create index oidc_artifacts_user_code_idx on oidc_artifacts (user_code);
create index oidc_artifacts_expiry_idx on oidc_artifacts (expires_at);
create table oidc_sessions (id text primary key, account_id text not null, auth_time integer not null, acr text,
  amr text, idp text, upstream_session_id text, clients text not null, expires_at integer not null);
create index oidc_sessions_account_idx on oidc_sessions (account_id);
create index oidc_sessions_upstream_idx on oidc_sessions (idp, upstream_session_id);
create table oidc_grants (id text primary key, account_id text not null, client_id text not null, scopes text not null,
  claims text not null, resources text not null, created_at integer not null, expires_at integer);
create unique index oidc_grants_account_client_idx on oidc_grants (account_id, client_id);
create table oidc_identities (provider text not null, subject text not null, account_id text not null, email text,
  claims text not null, linked_at integer not null, primary key (provider, subject));
create table oidc_replay (namespace text not null, value text not null, expires_at integer not null,
  primary key (namespace, value));
`

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
  for (const statement of MIGRATION.split(';')
    .map(s => s.trim())
    .filter(Boolean))
    sqlite.run(statement)
  const db = drizzle(sqlite) as unknown as DrizzleDatabase
  return { db, adapter: drizzleAdapter({ db, keys: await generatedKeyStore(), accounts }) }
}

describe('drizzle adapter', () => {
  // The same suite the memory adapter runs: passing both is what "interchangeable" means (FR-A4).
  adapterConformance('drizzle/sqlite', async () => (await fresh()).adapter)

  // FR-A5: the criticism of the blob-table shape only holds if this adapter avoids it.
  test('revocation is an indexed delete, not a scan', async () => {
    const { db } = await fresh()
    const plan = (db as unknown as { all: (q: unknown) => { detail: string }[] }).all(
      sql`explain query plan delete from oidc_artifacts where grant_id = 'g1'`
    )
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
