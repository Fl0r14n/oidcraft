import type { Migration } from './migration'

/**
 * The SQLite schema every SQL adapter queries, as ordered migrations the host applies with its own
 * tooling. The library never runs them: a library that migrates on import migrates during a rolling
 * deploy, from several processes at once (ARCHITECTURE.md §4.2, FR-A4).
 */

export const SQLITE_MIGRATIONS: Migration[] = [
  {
    id: '0001_init',
    statements: [
      'create table oidc_clients (client_id text primary key not null, data text not null, created_at integer not null, updated_at integer not null)',
      'create table oidc_artifacts (kind text not null, id text not null, client_id text not null, account_id text, grant_id text, user_code text, payload text not null, consumed_at integer, expires_at integer not null, primary key (kind, id))',
      'create index oidc_artifacts_grant_idx on oidc_artifacts (grant_id)',
      'create index oidc_artifacts_user_code_idx on oidc_artifacts (user_code)',
      'create index oidc_artifacts_expiry_idx on oidc_artifacts (expires_at)',
      'create table oidc_sessions (id text primary key not null, account_id text not null, auth_time integer not null, acr text, amr text, idp text, upstream_session_id text, clients text not null, expires_at integer not null)',
      'create index oidc_sessions_account_idx on oidc_sessions (account_id)',
      'create index oidc_sessions_upstream_idx on oidc_sessions (idp, upstream_session_id)',
      'create table oidc_grants (id text primary key not null, account_id text not null, client_id text not null, scopes text not null, claims text not null, resources text not null, created_at integer not null, expires_at integer)',
      'create unique index oidc_grants_account_client_idx on oidc_grants (account_id, client_id)',
      'create table oidc_identities (provider text not null, subject text not null, account_id text not null, email text, claims text not null, linked_at integer not null, primary key (provider, subject))',
      'create table oidc_replay (namespace text not null, value text not null, expires_at integer not null, primary key (namespace, value))'
    ]
  },
  {
    id: '0002_credentials',
    statements: [
      'create table oidc_credentials (account_id text primary key not null, username text not null, password_hash text, claims text not null, totp_secret text, totp_confirmed_at integer, recovery_codes text, failed_attempts integer not null default 0, locked_until integer, created_at integer not null, updated_at integer not null)',
      'create unique index oidc_credentials_username_idx on oidc_credentials (username)',
      'create index oidc_identities_account_idx on oidc_identities (account_id)',
      'create index oidc_replay_expiry_idx on oidc_replay (expires_at)'
    ]
  },
  {
    id: '0003_realms',
    statements: [
      'create table oidc_realms (id text primary key not null, display_name text, enabled integer not null, settings text not null, created_at integer not null, updated_at integer not null)'
    ]
  },
  {
    // FR-T7: deleting a client deletes what it holds, by client. NFR-P3: a sweep of expired sessions finds them by expiry (FR-A5).
    id: '0004_indexes',
    statements: [
      'create index oidc_artifacts_client_idx on oidc_artifacts (client_id)',
      'create index oidc_grants_client_idx on oidc_grants (client_id)',
      'create index oidc_sessions_expiry_idx on oidc_sessions (expires_at)'
    ]
  },
  {
    // FR-T3: a replay or a revoked refresh token ends one family, by one indexed delete (FR-A5).
    id: '0005_families',
    statements: [
      'alter table oidc_artifacts add column family_id text',
      'create index oidc_artifacts_family_idx on oidc_artifacts (family_id)'
    ]
  },
  {
    // FR-I8: an assertion is looked up by its credential id, an account's passkeys by the account.
    id: '0006_passkeys',
    statements: [
      'create table oidc_passkeys (credential_id text primary key not null, account_id text not null, public_key text not null, algorithm integer not null, counter integer not null, transports text not null, name text not null, created_at integer not null, last_used_at integer)',
      'create index oidc_passkeys_account_idx on oidc_passkeys (account_id)'
    ]
  }
]
export type { Migration } from './migration'
