import { EntitySchema, type EntitySchemaColumnOptions, type MigrationInterface, type QueryRunner } from 'typeorm'
import { type Migration, SQLITE_MIGRATIONS } from '../sql/sqlite'

export type ClientRow = { client_id: string; data: string; created_at: number; updated_at: number }

export type ArtifactRow = {
  kind: string
  id: string
  client_id: string
  account_id: string | null
  grant_id: string | null
  user_code: string | null
  payload: string
  consumed_at: number | null
  expires_at: number
}

export type SessionRow = {
  id: string
  account_id: string
  auth_time: number
  acr: string | null
  amr: string | null
  idp: string | null
  upstream_session_id: string | null
  clients: string
  expires_at: number
}

export type GrantRow = {
  id: string
  account_id: string
  client_id: string
  scopes: string
  claims: string
  resources: string
  created_at: number
  expires_at: number | null
}

export type IdentityRow = {
  provider: string
  subject: string
  account_id: string
  email: string | null
  claims: string
  linked_at: number
}

export type ReplayRow = { namespace: string; value: string; expires_at: number }

export type CredentialRow = {
  account_id: string
  username: string
  password_hash: string
  claims: string
  totp_secret: string | null
  totp_confirmed_at: number | null
  recovery_codes: string | null
  failed_attempts: number
  locked_until: number | null
  created_at: number
  updated_at: number
}

const text = (options: Partial<EntitySchemaColumnOptions> = {}): EntitySchemaColumnOptions => ({ type: 'text', ...options })

/** Milliseconds since the epoch. A driver may hand a bigint back as a string, which is not a date's number. */
const millis = (options: Partial<EntitySchemaColumnOptions> = {}): EntitySchemaColumnOptions => ({
  type: 'bigint',
  transformer: { to: (value: unknown) => value, from: (value: unknown) => (value === null || value === undefined ? value : Number(value)) },
  ...options
})

export const ClientEntity = new EntitySchema<ClientRow>({
  name: 'oidc_clients',
  tableName: 'oidc_clients',
  columns: { client_id: text({ primary: true }), data: text(), created_at: millis(), updated_at: millis() }
})

export const ArtifactEntity = new EntitySchema<ArtifactRow>({
  name: 'oidc_artifacts',
  tableName: 'oidc_artifacts',
  columns: {
    kind: text({ primary: true }),
    id: text({ primary: true }),
    client_id: text(),
    account_id: text({ nullable: true }),
    grant_id: text({ nullable: true }),
    user_code: text({ nullable: true }),
    payload: text(),
    consumed_at: millis({ nullable: true }),
    expires_at: millis()
  },
  indices: [
    { name: 'oidc_artifacts_grant_idx', columns: ['grant_id'] },
    { name: 'oidc_artifacts_user_code_idx', columns: ['user_code'] },
    { name: 'oidc_artifacts_expiry_idx', columns: ['expires_at'] }
  ]
})

export const SessionEntity = new EntitySchema<SessionRow>({
  name: 'oidc_sessions',
  tableName: 'oidc_sessions',
  columns: {
    id: text({ primary: true }),
    account_id: text(),
    auth_time: millis(),
    acr: text({ nullable: true }),
    amr: text({ nullable: true }),
    idp: text({ nullable: true }),
    upstream_session_id: text({ nullable: true }),
    clients: text(),
    expires_at: millis()
  },
  indices: [
    { name: 'oidc_sessions_account_idx', columns: ['account_id'] },
    { name: 'oidc_sessions_upstream_idx', columns: ['idp', 'upstream_session_id'] }
  ]
})

export const GrantEntity = new EntitySchema<GrantRow>({
  name: 'oidc_grants',
  tableName: 'oidc_grants',
  columns: {
    id: text({ primary: true }),
    account_id: text(),
    client_id: text(),
    scopes: text(),
    claims: text(),
    resources: text(),
    created_at: millis(),
    expires_at: millis({ nullable: true })
  },
  indices: [{ name: 'oidc_grants_account_client_idx', columns: ['account_id', 'client_id'], unique: true }]
})

export const IdentityEntity = new EntitySchema<IdentityRow>({
  name: 'oidc_identities',
  tableName: 'oidc_identities',
  columns: {
    provider: text({ primary: true }),
    subject: text({ primary: true }),
    account_id: text(),
    email: text({ nullable: true }),
    claims: text(),
    linked_at: millis()
  },
  indices: [{ name: 'oidc_identities_account_idx', columns: ['account_id'] }]
})

export const ReplayEntity = new EntitySchema<ReplayRow>({
  name: 'oidc_replay',
  tableName: 'oidc_replay',
  columns: { namespace: text({ primary: true }), value: text({ primary: true }), expires_at: millis() },
  indices: [{ name: 'oidc_replay_expiry_idx', columns: ['expires_at'] }]
})

export const CredentialEntity = new EntitySchema<CredentialRow>({
  name: 'oidc_credentials',
  tableName: 'oidc_credentials',
  columns: {
    account_id: text({ primary: true }),
    username: text(),
    password_hash: text(),
    claims: text(),
    totp_secret: text({ nullable: true }),
    totp_confirmed_at: millis({ nullable: true }),
    recovery_codes: text({ nullable: true }),
    failed_attempts: { type: 'integer', default: 0 },
    locked_until: millis({ nullable: true }),
    created_at: millis(),
    updated_at: millis()
  },
  indices: [{ name: 'oidc_credentials_username_idx', columns: ['username'], unique: true }]
})

/** Register these with the host's `DataSource`; the adapter refuses one that lacks them. */
export const OIDCRAFT_ENTITIES = [ClientEntity, ArtifactEntity, SessionEntity, GrantEntity, IdentityEntity, ReplayEntity, CredentialEntity]

/**
 * TypeORM reads a migration's order from a 13-digit timestamp at the end of its class name. These
 * are fixed and early, so they order among themselves and never depend on when a host installed them.
 */
const asTypeormMigration = (migration: Migration, index: number) => {
  const name = `Oidcraft${migration.id.replace(/^\d+_/, '').replace(/(^|_)(\w)/g, (_, __, c: string) => c.toUpperCase())}${1000000000000 + index + 1}`
  const Class = class implements MigrationInterface {
    name = name
    async up(queryRunner: QueryRunner) {
      for (const statement of migration.statements) await queryRunner.query(statement)
    }
    async down(): Promise<void> {
      throw new Error(`${name} is forward-only, like every oidcraft migration`)
    }
  }
  Object.defineProperty(Class, 'name', { value: name })
  return Class
}

/** The shared SQLite schema (FR-A4) as TypeORM migration classes, for the host's `DataSource.migrations`. */
export const TYPEORM_SQLITE_MIGRATIONS = SQLITE_MIGRATIONS.map(asTypeormMigration)
