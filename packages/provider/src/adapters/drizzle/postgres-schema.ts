import { customType, index, integer, pgSchema, pgTable, primaryKey, text, uniqueIndex } from 'drizzle-orm/pg-core'

// Columns that read and write what the SQLite schema's do — a Date, parsed JSON, a boolean — over the
// shared POSTGRES_MIGRATIONS tables, so one adapter serves both dialects.
const millis = customType<{ data: Date; driverData: string | number }>({
  dataType: () => 'bigint',
  toDriver: value => value.getTime(),
  fromDriver: value => new Date(Number(value))
})
const json = customType<{ data: unknown; driverData: string }>({
  dataType: () => 'text',
  toDriver: value => JSON.stringify(value),
  fromDriver: value => JSON.parse(value)
})
const flag = customType<{ data: boolean; driverData: number }>({
  dataType: () => 'integer',
  toDriver: value => (value ? 1 : 0),
  fromDriver: value => Boolean(value)
})

/**
 * The oidcraft tables for Postgres, in `schema` or in the search path when it is omitted. A factory,
 * because Drizzle fixes a table's schema when the table is defined: a realm with a schema of its own
 * (G-6) needs tables of its own. Pass the result as `drizzleAdapter`'s `tables`.
 */
export const postgresTables = (schema?: string) => {
  const table = (schema ? pgSchema(schema).table.bind(pgSchema(schema)) : pgTable) as typeof pgTable

  const clients = table('oidc_clients', {
    clientId: text('client_id').primaryKey(),
    data: json('data').notNull(),
    createdAt: millis('created_at').notNull(),
    updatedAt: millis('updated_at').notNull()
  })

  const artifacts = table(
    'oidc_artifacts',
    {
      kind: text('kind').notNull(),
      id: text('id').notNull(),
      clientId: text('client_id').notNull(),
      accountId: text('account_id'),
      grantId: text('grant_id'),
      userCode: text('user_code'),
      payload: json('payload').notNull(),
      consumedAt: millis('consumed_at'),
      expiresAt: millis('expires_at').notNull()
    },
    t => [
      primaryKey({ columns: [t.kind, t.id] }),
      index('oidc_artifacts_grant_idx').on(t.grantId),
      index('oidc_artifacts_user_code_idx').on(t.userCode),
      index('oidc_artifacts_expiry_idx').on(t.expiresAt)
    ]
  )

  const sessions = table(
    'oidc_sessions',
    {
      id: text('id').primaryKey(),
      accountId: text('account_id').notNull(),
      authTime: millis('auth_time').notNull(),
      acr: text('acr'),
      amr: json('amr'),
      idp: text('idp'),
      upstreamSessionId: text('upstream_session_id'),
      clients: json('clients').notNull(),
      expiresAt: millis('expires_at').notNull()
    },
    t => [index('oidc_sessions_account_idx').on(t.accountId), index('oidc_sessions_upstream_idx').on(t.idp, t.upstreamSessionId)]
  )

  const grants = table(
    'oidc_grants',
    {
      id: text('id').primaryKey(),
      accountId: text('account_id').notNull(),
      clientId: text('client_id').notNull(),
      scopes: json('scopes').notNull(),
      claims: json('claims').notNull(),
      resources: json('resources').notNull(),
      createdAt: millis('created_at').notNull(),
      expiresAt: millis('expires_at')
    },
    t => [uniqueIndex('oidc_grants_account_client_idx').on(t.accountId, t.clientId)]
  )

  const identities = table(
    'oidc_identities',
    {
      provider: text('provider').notNull(),
      subject: text('subject').notNull(),
      accountId: text('account_id').notNull(),
      email: text('email'),
      claims: json('claims').notNull(),
      linkedAt: millis('linked_at').notNull()
    },
    t => [primaryKey({ columns: [t.provider, t.subject] }), index('oidc_identities_account_idx').on(t.accountId)]
  )

  const replay = table(
    'oidc_replay',
    {
      namespace: text('namespace').notNull(),
      value: text('value').notNull(),
      expiresAt: millis('expires_at').notNull()
    },
    t => [primaryKey({ columns: [t.namespace, t.value] }), index('oidc_replay_expiry_idx').on(t.expiresAt)]
  )

  const credentials = table(
    'oidc_credentials',
    {
      accountId: text('account_id').primaryKey(),
      username: text('username').notNull(),
      passwordHash: text('password_hash').notNull(),
      claims: json('claims').notNull(),
      totpSecret: text('totp_secret'),
      totpConfirmedAt: millis('totp_confirmed_at'),
      recoveryCodes: json('recovery_codes'),
      failedAttempts: integer('failed_attempts').notNull().default(0),
      lockedUntil: millis('locked_until'),
      createdAt: millis('created_at').notNull(),
      updatedAt: millis('updated_at').notNull()
    },
    t => [uniqueIndex('oidc_credentials_username_idx').on(t.username)]
  )

  const realms = table('oidc_realms', {
    id: text('id').primaryKey(),
    displayName: text('display_name'),
    enabled: flag('enabled').notNull(),
    settings: json('settings').notNull(),
    createdAt: millis('created_at').notNull(),
    updatedAt: millis('updated_at').notNull()
  })

  return { clients, artifacts, sessions, grants, identities, replay, credentials, realms }
}

export type PostgresTables = ReturnType<typeof postgresTables>
