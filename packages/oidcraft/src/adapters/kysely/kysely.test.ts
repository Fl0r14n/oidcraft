/// <reference types="bun" />

import { Database } from 'bun:sqlite'
import { describe, expect, test } from 'bun:test'
import { Kysely, sql } from 'kysely'
import { BunSqliteDialect } from 'kysely-bun-sqlite'
import { adapterConformance } from '../../adapter-conformance'
import { generatedKeyStore } from '../../keys'
import { kyselyAdapter, type OidcraftDatabase } from './index'

const MIGRATION = `
create table oidc_clients (client_id text primary key, data text not null, created_at integer not null, updated_at integer not null);
create table oidc_artifacts (kind text not null, id text not null, client_id text not null, account_id text,
  grant_id text, user_code text, payload text not null, consumed_at integer, expires_at integer not null,
  primary key (kind, id));
create index oidc_artifacts_grant_idx on oidc_artifacts (grant_id);
create index oidc_artifacts_user_code_idx on oidc_artifacts (user_code);
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
