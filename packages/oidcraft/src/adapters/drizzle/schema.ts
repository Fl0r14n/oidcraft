import { index, integer, primaryKey, sqliteTable, text, uniqueIndex } from 'drizzle-orm/sqlite-core'

/**
 * Real columns and real indexes for every value the core queries by (FR-A5).
 *
 * The shape a key-value adapter is forced into — one row of JSON per artifact — turns revocation
 * and the user-code lookup into full scans. Those are on the hot path of every token request, so a
 * relational adapter must not reproduce it.
 */
export const clients = sqliteTable('oidc_clients', {
  clientId: text('client_id').primaryKey(),
  data: text('data', { mode: 'json' }).notNull(),
  createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull(),
  updatedAt: integer('updated_at', { mode: 'timestamp_ms' }).notNull()
})

export const artifacts = sqliteTable(
  'oidc_artifacts',
  {
    kind: text('kind').notNull(),
    id: text('id').notNull(),
    clientId: text('client_id').notNull(),
    accountId: text('account_id'),
    grantId: text('grant_id'),
    userCode: text('user_code'),
    payload: text('payload', { mode: 'json' }).notNull(),
    consumedAt: integer('consumed_at', { mode: 'timestamp_ms' }),
    expiresAt: integer('expires_at', { mode: 'timestamp_ms' }).notNull()
  },
  table => [
    primaryKey({ columns: [table.kind, table.id] }),
    // Revocation is a range delete over this, not a scan (FR-A5).
    index('oidc_artifacts_grant_idx').on(table.grantId),
    index('oidc_artifacts_user_code_idx').on(table.userCode),
    index('oidc_artifacts_expiry_idx').on(table.expiresAt)
  ]
)

export const sessions = sqliteTable(
  'oidc_sessions',
  {
    id: text('id').primaryKey(),
    accountId: text('account_id').notNull(),
    authTime: integer('auth_time', { mode: 'timestamp_ms' }).notNull(),
    acr: text('acr'),
    amr: text('amr', { mode: 'json' }),
    idp: text('idp'),
    upstreamSessionId: text('upstream_session_id'),
    clients: text('clients', { mode: 'json' }).notNull(),
    expiresAt: integer('expires_at', { mode: 'timestamp_ms' }).notNull()
  },
  table => [
    index('oidc_sessions_account_idx').on(table.accountId),
    // Upstream back-channel logout arrives keyed by this, not by our session id (FR-F8).
    index('oidc_sessions_upstream_idx').on(table.idp, table.upstreamSessionId),
    index('oidc_sessions_expiry_idx').on(table.expiresAt)
  ]
)

export const grants = sqliteTable(
  'oidc_grants',
  {
    id: text('id').primaryKey(),
    accountId: text('account_id').notNull(),
    clientId: text('client_id').notNull(),
    scopes: text('scopes', { mode: 'json' }).notNull(),
    claims: text('claims', { mode: 'json' }).notNull(),
    resources: text('resources', { mode: 'json' }).notNull(),
    createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull(),
    expiresAt: integer('expires_at', { mode: 'timestamp_ms' })
  },
  table => [
    // One grant per (account, client): the consent record accumulates rather than duplicating.
    uniqueIndex('oidc_grants_account_client_idx').on(table.accountId, table.clientId)
  ]
)

export const identities = sqliteTable(
  'oidc_identities',
  {
    provider: text('provider').notNull(),
    subject: text('subject').notNull(),
    accountId: text('account_id').notNull(),
    email: text('email'),
    claims: text('claims', { mode: 'json' }).notNull(),
    linkedAt: integer('linked_at', { mode: 'timestamp_ms' }).notNull()
  },
  table => [primaryKey({ columns: [table.provider, table.subject] }), index('oidc_identities_account_idx').on(table.accountId)]
)

export const replay = sqliteTable(
  'oidc_replay',
  {
    namespace: text('namespace').notNull(),
    value: text('value').notNull(),
    expiresAt: integer('expires_at', { mode: 'timestamp_ms' }).notNull()
  },
  table => [primaryKey({ columns: [table.namespace, table.value] }), index('oidc_replay_expiry_idx').on(table.expiresAt)]
)

export const schema = { clients, artifacts, sessions, grants, identities, replay }
