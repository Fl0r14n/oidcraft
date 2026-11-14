import { bigint, customType, index, int, mysqlSchema, mysqlTable, primaryKey, text, uniqueIndex, varchar } from 'drizzle-orm/mysql-core'

// The same JS values as the SQLite and Postgres columns, over MYSQL_MIGRATIONS' types: one table set for MySQL and MariaDB.
const millis = customType<{ data: Date; driverData: string | number }>({
  dataType: () => 'bigint',
  toDriver: value => value.getTime(),
  fromDriver: value => new Date(Number(value))
})
const json = customType<{ data: unknown; driverData: string }>({
  dataType: () => 'mediumtext',
  toDriver: value => JSON.stringify(value),
  fromDriver: value => JSON.parse(value)
})
const jsonText = customType<{ data: unknown; driverData: string }>({
  dataType: () => 'text',
  toDriver: value => JSON.stringify(value),
  fromDriver: value => JSON.parse(value)
})
const flag = customType<{ data: boolean; driverData: number }>({
  dataType: () => 'integer',
  toDriver: value => (value ? 1 : 0),
  fromDriver: value => Boolean(value)
})

/** `drizzleAdapter`'s `tables` on MySQL or MariaDB, in `database` or the connection's; a realm owns a database (G-6). */
export const mysqlTables = (database?: string) => {
  const table = (database ? mysqlSchema(database).table.bind(mysqlSchema(database)) : mysqlTable) as typeof mysqlTable

  const clients = table('oidc_clients', {
    clientId: varchar('client_id', { length: 512 }).primaryKey(),
    data: json('data').notNull(),
    createdAt: millis('created_at').notNull(),
    updatedAt: millis('updated_at').notNull()
  })

  const artifacts = table(
    'oidc_artifacts',
    {
      kind: varchar('kind', { length: 64 }).notNull(),
      id: varchar('id', { length: 255 }).notNull(),
      clientId: varchar('client_id', { length: 512 }).notNull(),
      accountId: varchar('account_id', { length: 255 }),
      grantId: varchar('grant_id', { length: 255 }),
      familyId: varchar('family_id', { length: 255 }),
      userCode: varchar('user_code', { length: 255 }),
      payload: json('payload').notNull(),
      consumedAt: millis('consumed_at'),
      expiresAt: millis('expires_at').notNull()
    },
    t => [
      primaryKey({ columns: [t.kind, t.id] }),
      index('oidc_artifacts_grant_idx').on(t.grantId),
      index('oidc_artifacts_user_code_idx').on(t.userCode),
      index('oidc_artifacts_expiry_idx').on(t.expiresAt),
      index('oidc_artifacts_client_idx').on(t.clientId),
      index('oidc_artifacts_family_idx').on(t.familyId)
    ]
  )

  const sessions = table(
    'oidc_sessions',
    {
      id: varchar('id', { length: 255 }).primaryKey(),
      accountId: varchar('account_id', { length: 255 }).notNull(),
      authTime: millis('auth_time').notNull(),
      acr: text('acr'),
      amr: jsonText('amr'),
      idp: varchar('idp', { length: 255 }),
      upstreamSessionId: varchar('upstream_session_id', { length: 255 }),
      clients: json('clients').notNull(),
      expiresAt: millis('expires_at').notNull()
    },
    t => [
      index('oidc_sessions_account_idx').on(t.accountId),
      index('oidc_sessions_upstream_idx').on(t.idp, t.upstreamSessionId),
      index('oidc_sessions_expiry_idx').on(t.expiresAt)
    ]
  )

  const grants = table(
    'oidc_grants',
    {
      id: varchar('id', { length: 255 }).primaryKey(),
      accountId: varchar('account_id', { length: 255 }).notNull(),
      clientId: varchar('client_id', { length: 512 }).notNull(),
      scopes: json('scopes').notNull(),
      claims: json('claims').notNull(),
      resources: json('resources').notNull(),
      createdAt: millis('created_at').notNull(),
      expiresAt: millis('expires_at')
    },
    t => [uniqueIndex('oidc_grants_account_client_idx').on(t.accountId, t.clientId), index('oidc_grants_client_idx').on(t.clientId)]
  )

  const identities = table(
    'oidc_identities',
    {
      provider: varchar('provider', { length: 255 }).notNull(),
      subject: varchar('subject', { length: 255 }).notNull(),
      accountId: varchar('account_id', { length: 255 }).notNull(),
      email: text('email'),
      claims: json('claims').notNull(),
      linkedAt: millis('linked_at').notNull()
    },
    t => [primaryKey({ columns: [t.provider, t.subject] }), index('oidc_identities_account_idx').on(t.accountId)]
  )

  const replay = table(
    'oidc_replay',
    {
      namespace: varchar('namespace', { length: 255 }).notNull(),
      value: varchar('value', { length: 64 }).notNull(),
      expiresAt: millis('expires_at').notNull()
    },
    t => [primaryKey({ columns: [t.namespace, t.value] }), index('oidc_replay_expiry_idx').on(t.expiresAt)]
  )

  const credentials = table(
    'oidc_credentials',
    {
      accountId: varchar('account_id', { length: 255 }).primaryKey(),
      username: varchar('username', { length: 255 }).notNull(),
      passwordHash: text('password_hash'),
      claims: json('claims').notNull(),
      totpSecret: text('totp_secret'),
      totpConfirmedAt: millis('totp_confirmed_at'),
      recoveryCodes: jsonText('recovery_codes'),
      failedAttempts: int('failed_attempts').notNull().default(0),
      lockedUntil: millis('locked_until'),
      createdAt: millis('created_at').notNull(),
      updatedAt: millis('updated_at').notNull()
    },
    t => [uniqueIndex('oidc_credentials_username_idx').on(t.username)]
  )

  const passkeys = table(
    'oidc_passkeys',
    {
      credentialId: varchar('credential_id', { length: 1400 }).primaryKey(),
      accountId: varchar('account_id', { length: 255 }).notNull(),
      publicKey: text('public_key').notNull(),
      algorithm: int('algorithm').notNull(),
      counter: bigint('counter', { mode: 'number' }).notNull(),
      transports: jsonText('transports').notNull(),
      name: varchar('name', { length: 255 }).notNull(),
      createdAt: millis('created_at').notNull(),
      lastUsedAt: millis('last_used_at')
    },
    t => [index('oidc_passkeys_account_idx').on(t.accountId)]
  )

  const realms = table('oidc_realms', {
    id: varchar('id', { length: 255 }).primaryKey(),
    displayName: text('display_name'),
    enabled: flag('enabled').notNull(),
    settings: json('settings').notNull(),
    createdAt: millis('created_at').notNull(),
    updatedAt: millis('updated_at').notNull()
  })

  return { clients, artifacts, sessions, grants, identities, replay, credentials, passkeys, realms }
}

export type MysqlTables = ReturnType<typeof mysqlTables>
