import type { Migration } from './sqlite'

/**
 * The same tables as `SQLITE_MIGRATIONS`, with the same ids, for Postgres (FR-A4). Milliseconds are
 * `bigint` and JSON stays `text`, so every adapter reads and writes exactly what it does on SQLite.
 * Table names are unqualified: they land in whatever schema the host migrates into, which is how a
 * realm gets a schema of its own in one database (G-6).
 */
export const POSTGRES_MIGRATIONS: Migration[] = [
  {
    id: '0001_init',
    statements: [
      'create table oidc_clients (client_id text primary key, data text not null, created_at bigint not null, updated_at bigint not null)',
      'create table oidc_artifacts (kind text not null, id text not null, client_id text not null, account_id text, grant_id text, user_code text, payload text not null, consumed_at bigint, expires_at bigint not null, primary key (kind, id))',
      'create index oidc_artifacts_grant_idx on oidc_artifacts (grant_id)',
      'create index oidc_artifacts_user_code_idx on oidc_artifacts (user_code)',
      'create index oidc_artifacts_expiry_idx on oidc_artifacts (expires_at)',
      'create table oidc_sessions (id text primary key, account_id text not null, auth_time bigint not null, acr text, amr text, idp text, upstream_session_id text, clients text not null, expires_at bigint not null)',
      'create index oidc_sessions_account_idx on oidc_sessions (account_id)',
      'create index oidc_sessions_upstream_idx on oidc_sessions (idp, upstream_session_id)',
      'create table oidc_grants (id text primary key, account_id text not null, client_id text not null, scopes text not null, claims text not null, resources text not null, created_at bigint not null, expires_at bigint)',
      'create unique index oidc_grants_account_client_idx on oidc_grants (account_id, client_id)',
      'create table oidc_identities (provider text not null, subject text not null, account_id text not null, email text, claims text not null, linked_at bigint not null, primary key (provider, subject))',
      'create table oidc_replay (namespace text not null, value text not null, expires_at bigint not null, primary key (namespace, value))'
    ]
  },
  {
    id: '0002_credentials',
    statements: [
      'create table oidc_credentials (account_id text primary key, username text not null, password_hash text not null, claims text not null, totp_secret text, totp_confirmed_at bigint, recovery_codes text, failed_attempts integer not null default 0, locked_until bigint, created_at bigint not null, updated_at bigint not null)',
      'create unique index oidc_credentials_username_idx on oidc_credentials (username)',
      'create index oidc_identities_account_idx on oidc_identities (account_id)',
      'create index oidc_replay_expiry_idx on oidc_replay (expires_at)'
    ]
  },
  {
    id: '0003_realms',
    statements: [
      'create table oidc_realms (id text primary key, display_name text, enabled integer not null, settings text not null, created_at bigint not null, updated_at bigint not null)'
    ]
  }
]
