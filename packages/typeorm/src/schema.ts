import { POSTGRES_MIGRATIONS } from '@oidcraft/sql/postgres'
import type { ArtifactRow, ClientRow, CredentialRow, GrantRow, IdentityRow, RealmRow, ReplayRow, SessionRow } from '@oidcraft/sql/rows'
import { type Migration, SQLITE_MIGRATIONS } from '@oidcraft/sql/sqlite'
import { EntitySchema, type EntitySchemaColumnOptions, type MigrationInterface, type QueryRunner } from 'typeorm'

export type { ArtifactRow, ClientRow, CredentialRow, GrantRow, IdentityRow, RealmRow, ReplayRow, SessionRow }

const text = (options: Partial<EntitySchemaColumnOptions> = {}): EntitySchemaColumnOptions => ({ type: 'text', ...options })

/**
 * The entities over one dialect's tables. Epoch milliseconds are SQLite's `integer` and Postgres's `bigint`, as the
 * migrations make them: one type for both, and TypeORM's schema builder would rebuild every table of the other (FR-A4).
 */
const entitiesFor = (millisType: 'integer' | 'bigint') => {
  // a driver may hand a `bigint` back as a string, so it is read back through `Number`
  const millis = (options: Partial<EntitySchemaColumnOptions> = {}): EntitySchemaColumnOptions => ({
    type: millisType,
    transformer: {
      to: (value: unknown) => value,
      from: (value: unknown) => (value === null || value === undefined ? value : Number(value))
    },
    ...options
  })

  const ClientEntity = new EntitySchema<ClientRow>({
    name: 'oidc_clients',
    tableName: 'oidc_clients',
    columns: { client_id: text({ primary: true }), data: text(), created_at: millis(), updated_at: millis() }
  })

  const ArtifactEntity = new EntitySchema<ArtifactRow>({
    name: 'oidc_artifacts',
    tableName: 'oidc_artifacts',
    columns: {
      kind: text({ primary: true }),
      id: text({ primary: true }),
      client_id: text(),
      account_id: text({ nullable: true }),
      grant_id: text({ nullable: true }),
      family_id: text({ nullable: true }),
      user_code: text({ nullable: true }),
      payload: text(),
      consumed_at: millis({ nullable: true }),
      expires_at: millis()
    },
    indices: [
      { name: 'oidc_artifacts_grant_idx', columns: ['grant_id'] },
      { name: 'oidc_artifacts_user_code_idx', columns: ['user_code'] },
      { name: 'oidc_artifacts_expiry_idx', columns: ['expires_at'] },
      { name: 'oidc_artifacts_client_idx', columns: ['client_id'] },
      { name: 'oidc_artifacts_family_idx', columns: ['family_id'] }
    ]
  })

  const SessionEntity = new EntitySchema<SessionRow>({
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
      { name: 'oidc_sessions_upstream_idx', columns: ['idp', 'upstream_session_id'] },
      { name: 'oidc_sessions_expiry_idx', columns: ['expires_at'] }
    ]
  })

  const GrantEntity = new EntitySchema<GrantRow>({
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
    indices: [
      { name: 'oidc_grants_account_client_idx', columns: ['account_id', 'client_id'], unique: true },
      { name: 'oidc_grants_client_idx', columns: ['client_id'] }
    ]
  })

  const IdentityEntity = new EntitySchema<IdentityRow>({
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

  const ReplayEntity = new EntitySchema<ReplayRow>({
    name: 'oidc_replay',
    tableName: 'oidc_replay',
    columns: { namespace: text({ primary: true }), value: text({ primary: true }), expires_at: millis() },
    indices: [{ name: 'oidc_replay_expiry_idx', columns: ['expires_at'] }]
  })

  const CredentialEntity = new EntitySchema<CredentialRow>({
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

  const RealmEntity = new EntitySchema<RealmRow>({
    name: 'oidc_realms',
    tableName: 'oidc_realms',
    columns: {
      id: text({ primary: true }),
      display_name: text({ nullable: true }),
      enabled: { type: 'integer' },
      settings: text(),
      created_at: millis(),
      updated_at: millis()
    }
  })

  return [ClientEntity, ArtifactEntity, SessionEntity, GrantEntity, IdentityEntity, ReplayEntity, CredentialEntity, RealmEntity]
}

/** For a `DataSource` on SQLite, beside `TYPEORM_SQLITE_MIGRATIONS`; the adapter refuses one that lacks them. */
export const OIDCRAFT_SQLITE_ENTITIES = entitiesFor('integer')

/** For a `DataSource` on Postgres, beside `TYPEORM_POSTGRES_MIGRATIONS`. */
export const OIDCRAFT_POSTGRES_ENTITIES = entitiesFor('bigint')

/** The tables both sets map, which the adapter reaches by name whichever set the host registered. */
export const OIDCRAFT_TABLES = OIDCRAFT_SQLITE_ENTITIES.map(entity => entity.options.name)

// TypeORM orders migrations by a 13-digit timestamp ending the class name; these are fixed and early, never install-time.
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

/** The same, for Postgres; the classes carry the same names, so a host runs one set or the other. */
export const TYPEORM_POSTGRES_MIGRATIONS = POSTGRES_MIGRATIONS.map(asTypeormMigration)
