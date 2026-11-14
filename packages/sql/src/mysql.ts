import type { Migration } from './migration'

// Every id here is a case-sensitive hash or random string, and MySQL's default collations compare case-insensitively.
const TABLE = 'engine=InnoDB default charset=utf8mb4 collate=utf8mb4_bin'

/**
 * The same tables as `SQLITE_MIGRATIONS`, with the same ids, for MySQL 8.4 and MariaDB 11 alike (FR-A4): one
 * dialect, written to what both accept. Keys are `varchar`, since InnoDB keys a `text` column only by a prefix, sized
 * so each index stays under its 3072 bytes; milliseconds are `bigint` and JSON stays text, as on Postgres.
 */
export const MYSQL_MIGRATIONS: Migration[] = [
  {
    id: '0001_init',
    statements: [
      `create table oidc_clients (client_id varchar(512) primary key, data mediumtext not null, created_at bigint not null, updated_at bigint not null) ${TABLE}`,
      `create table oidc_artifacts (kind varchar(64) not null, id varchar(255) not null, client_id varchar(512) not null, account_id varchar(255), grant_id varchar(255), user_code varchar(255), payload mediumtext not null, consumed_at bigint, expires_at bigint not null, primary key (kind, id)) ${TABLE}`,
      'create index oidc_artifacts_grant_idx on oidc_artifacts (grant_id)',
      'create index oidc_artifacts_user_code_idx on oidc_artifacts (user_code)',
      'create index oidc_artifacts_expiry_idx on oidc_artifacts (expires_at)',
      `create table oidc_sessions (id varchar(255) primary key, account_id varchar(255) not null, auth_time bigint not null, acr text, amr text, idp varchar(255), upstream_session_id varchar(255), clients mediumtext not null, expires_at bigint not null) ${TABLE}`,
      'create index oidc_sessions_account_idx on oidc_sessions (account_id)',
      'create index oidc_sessions_upstream_idx on oidc_sessions (idp, upstream_session_id)',
      `create table oidc_grants (id varchar(255) primary key, account_id varchar(255) not null, client_id varchar(512) not null, scopes mediumtext not null, claims mediumtext not null, resources mediumtext not null, created_at bigint not null, expires_at bigint) ${TABLE}`,
      'create unique index oidc_grants_account_client_idx on oidc_grants (account_id, client_id)',
      `create table oidc_identities (provider varchar(255) not null, subject varchar(255) not null, account_id varchar(255) not null, email text, claims mediumtext not null, linked_at bigint not null, primary key (provider, subject)) ${TABLE}`,
      // NFR-S5: a claimed value is often a client's jti, of any length, so the adapters store its SHA-256 here.
      `create table oidc_replay (namespace varchar(255) not null, value varchar(64) not null, expires_at bigint not null, primary key (namespace, value)) ${TABLE}`
    ]
  },
  {
    id: '0002_credentials',
    statements: [
      `create table oidc_credentials (account_id varchar(255) primary key, username varchar(255) not null, password_hash text, claims mediumtext not null, totp_secret text, totp_confirmed_at bigint, recovery_codes text, failed_attempts integer not null default 0, locked_until bigint, created_at bigint not null, updated_at bigint not null) ${TABLE}`,
      'create unique index oidc_credentials_username_idx on oidc_credentials (username)',
      'create index oidc_identities_account_idx on oidc_identities (account_id)',
      'create index oidc_replay_expiry_idx on oidc_replay (expires_at)'
    ]
  },
  {
    id: '0003_realms',
    statements: [
      `create table oidc_realms (id varchar(255) primary key, display_name text, enabled integer not null, settings mediumtext not null, created_at bigint not null, updated_at bigint not null) ${TABLE}`
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
      'alter table oidc_artifacts add column family_id varchar(255)',
      'create index oidc_artifacts_family_idx on oidc_artifacts (family_id)'
    ]
  },
  {
    // FR-I8: a credential id is up to 1023 bytes, 1364 in base64url, which fits a key only as ascii.
    id: '0006_passkeys',
    statements: [
      `create table oidc_passkeys (credential_id varchar(1400) character set ascii collate ascii_bin primary key, account_id varchar(255) not null, public_key text not null, algorithm integer not null, counter bigint not null, transports text not null, name varchar(255) not null, created_at bigint not null, last_used_at bigint) ${TABLE}`,
      'create index oidc_passkeys_account_idx on oidc_passkeys (account_id)'
    ]
  }
]
export type { Migration } from './migration'
