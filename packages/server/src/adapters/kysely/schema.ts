import type { ColumnType, Generated } from 'kysely'

/** Milliseconds since the epoch: SQLite has no date type, and Postgres/MySQL round-trip an integer fine. */
type Millis = ColumnType<number, number, number>

export type ClientsTable = {
  client_id: string
  data: string
  created_at: Millis
  updated_at: Millis
}

export type ArtifactsTable = {
  kind: string
  id: string
  client_id: string
  account_id: string | null
  grant_id: string | null
  user_code: string | null
  payload: string
  consumed_at: Millis | null
  expires_at: Millis
}

export type SessionsTable = {
  id: string
  account_id: string
  auth_time: Millis
  acr: string | null
  amr: string | null
  idp: string | null
  upstream_session_id: string | null
  clients: string
  expires_at: Millis
}

export type GrantsTable = {
  id: string
  account_id: string
  client_id: string
  scopes: string
  claims: string
  resources: string
  created_at: Millis
  expires_at: Millis | null
}

export type IdentitiesTable = {
  provider: string
  subject: string
  account_id: string
  email: string | null
  claims: string
  linked_at: Millis
}

export type ReplayTable = {
  namespace: string
  value: string
  expires_at: Millis
}

export type CredentialsTable = {
  account_id: string
  username: string
  password_hash: string
  claims: string
  totp_secret: string | null
  totp_confirmed_at: Millis | null
  recovery_codes: string | null
  failed_attempts: number
  locked_until: Millis | null
  created_at: Millis
  updated_at: Millis
}

export type RealmsTable = {
  id: string
  display_name: string | null
  /** 0 or 1: SQLite has no boolean. */
  enabled: number
  settings: string
  created_at: Millis
  updated_at: Millis
}

export type OidcraftDatabase = {
  oidc_clients: ClientsTable
  oidc_artifacts: ArtifactsTable
  oidc_sessions: SessionsTable
  oidc_grants: GrantsTable
  oidc_identities: IdentitiesTable
  oidc_replay: ReplayTable
  oidc_credentials: CredentialsTable
  oidc_realms: RealmsTable
}

export type { Generated }
