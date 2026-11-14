import { MYSQL_MIGRATIONS } from '@oidcraft/sql/mysql'
import { POSTGRES_MIGRATIONS } from '@oidcraft/sql/postgres'
import type {
  ArtifactRow,
  ClientRow,
  CredentialRow,
  GrantRow,
  IdentityRow,
  PasskeyRow,
  RealmRow,
  ReplayRow,
  SessionRow
} from '@oidcraft/sql/rows'
import { type Migration, SQLITE_MIGRATIONS } from '@oidcraft/sql/sqlite'
import { EntitySchema, type EntitySchemaColumnOptions, type MigrationInterface, type QueryRunner } from 'typeorm'

export type { ArtifactRow, ClientRow, CredentialRow, GrantRow, IdentityRow, PasskeyRow, RealmRow, ReplayRow, SessionRow }

const text = (options: Partial<EntitySchemaColumnOptions> = {}): EntitySchemaColumnOptions => ({ type: 'text', ...options })

/**
 * The entities over one dialect's tables, typed exactly as its migrations make them, or TypeORM's schema builder would
 * rebuild every table (FR-A4): epoch milliseconds are SQLite's `integer` and the others' `bigint`, and on MySQL a key
 * is a sized `varchar`, which InnoDB indexes whole, and JSON a `mediumtext`.
 */
const entitiesFor = (dialect: 'sqlite' | 'postgres' | 'mysql') => {
  const mysql = dialect === 'mysql'
  const millisType = dialect === 'sqlite' ? 'integer' : 'bigint'
  const key = (length: number, options: Partial<EntitySchemaColumnOptions> = {}): EntitySchemaColumnOptions =>
    mysql ? { type: 'varchar', length, ...options } : text(options)
  const document = (options: Partial<EntitySchemaColumnOptions> = {}): EntitySchemaColumnOptions =>
    mysql ? { type: 'mediumtext', ...options } : text(options)
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
    columns: { client_id: key(512, { primary: true }), data: document(), created_at: millis(), updated_at: millis() }
  })

  const ArtifactEntity = new EntitySchema<ArtifactRow>({
    name: 'oidc_artifacts',
    tableName: 'oidc_artifacts',
    columns: {
      kind: key(64, { primary: true }),
      id: key(255, { primary: true }),
      client_id: key(512),
      account_id: key(255, { nullable: true }),
      grant_id: key(255, { nullable: true }),
      family_id: key(255, { nullable: true }),
      user_code: key(255, { nullable: true }),
      payload: document(),
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
      id: key(255, { primary: true }),
      account_id: key(255),
      auth_time: millis(),
      acr: text({ nullable: true }),
      amr: text({ nullable: true }),
      idp: key(255, { nullable: true }),
      upstream_session_id: key(255, { nullable: true }),
      clients: document(),
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
      id: key(255, { primary: true }),
      account_id: key(255),
      client_id: key(512),
      scopes: document(),
      claims: document(),
      resources: document(),
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
      provider: key(255, { primary: true }),
      subject: key(255, { primary: true }),
      account_id: key(255),
      email: text({ nullable: true }),
      claims: document(),
      linked_at: millis()
    },
    indices: [{ name: 'oidc_identities_account_idx', columns: ['account_id'] }]
  })

  const ReplayEntity = new EntitySchema<ReplayRow>({
    name: 'oidc_replay',
    tableName: 'oidc_replay',
    columns: { namespace: key(255, { primary: true }), value: key(64, { primary: true }), expires_at: millis() },
    indices: [{ name: 'oidc_replay_expiry_idx', columns: ['expires_at'] }]
  })

  const CredentialEntity = new EntitySchema<CredentialRow>({
    name: 'oidc_credentials',
    tableName: 'oidc_credentials',
    columns: {
      account_id: key(255, { primary: true }),
      username: key(255),
      password_hash: text(),
      claims: document(),
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

  const PasskeyEntity = new EntitySchema<PasskeyRow>({
    name: 'oidc_passkeys',
    tableName: 'oidc_passkeys',
    columns: {
      // FR-I8: up to 1364 characters of base64url, which fits an InnoDB key only as ascii.
      credential_id: mysql
        ? { type: 'varchar', length: 1400, charset: 'ascii', collation: 'ascii_bin', primary: true }
        : text({ primary: true }),
      account_id: key(255),
      public_key: text(),
      algorithm: { type: 'integer' },
      // Up to 2^32 - 1, which outgrows Postgres's `integer`: the type the timestamps get.
      counter: millis(),
      transports: text(),
      name: key(255),
      created_at: millis(),
      last_used_at: millis({ nullable: true })
    },
    indices: [{ name: 'oidc_passkeys_account_idx', columns: ['account_id'] }]
  })

  const RealmEntity = new EntitySchema<RealmRow>({
    name: 'oidc_realms',
    tableName: 'oidc_realms',
    columns: {
      id: key(255, { primary: true }),
      display_name: text({ nullable: true }),
      enabled: { type: 'integer' },
      settings: document(),
      created_at: millis(),
      updated_at: millis()
    }
  })

  return [
    ClientEntity,
    ArtifactEntity,
    SessionEntity,
    GrantEntity,
    IdentityEntity,
    ReplayEntity,
    CredentialEntity,
    PasskeyEntity,
    RealmEntity
  ]
}

/** For a `DataSource` on SQLite, beside `TYPEORM_SQLITE_MIGRATIONS`; the adapter refuses one that lacks them. */
export const OIDCRAFT_SQLITE_ENTITIES = entitiesFor('sqlite')

/** For a `DataSource` on Postgres, beside `TYPEORM_POSTGRES_MIGRATIONS`. */
export const OIDCRAFT_POSTGRES_ENTITIES = entitiesFor('postgres')

/** For a `DataSource` of type `mysql` or `mariadb`, beside `TYPEORM_MYSQL_MIGRATIONS`: one set, as it is one dialect. */
export const OIDCRAFT_MYSQL_ENTITIES = entitiesFor('mysql')

/** The tables every set maps, which the adapter reaches by name whichever set the host registered. */
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

/** The same, for MySQL and MariaDB alike. */
export const TYPEORM_MYSQL_MIGRATIONS = MYSQL_MIGRATIONS.map(asTypeormMigration)
