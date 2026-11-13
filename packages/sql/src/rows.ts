import type { Artifact, ArtifactKind, Client, Credential, Grant, LinkedIdentity, Realm, Session } from '@oidcraft/adapter'

export type ClientRow = { client_id: string; data: string; created_at: number; updated_at: number }

export type ArtifactRow = {
  kind: string
  id: string
  client_id: string
  account_id: string | null
  grant_id: string | null
  family_id: string | null
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

export type RealmRow = {
  id: string
  display_name: string | null
  enabled: number
  settings: string
  created_at: number
  updated_at: number
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

/** A row as read back: Postgres returns a `bigint` as a string. */
export type Read<T> = { [K in keyof T]: T[K] extends number ? number | string : T[K] extends number | null ? number | string | null : T[K] }

/** Never `new Date` on the raw value: a string there is read as a date, not as milliseconds. */
export const at = (millis: number | string) => new Date(Number(millis))
export const json = (value: unknown) => JSON.stringify(value)
export const parse = <T>(value: string) => JSON.parse(value) as T

export const clientRow = (client: Client): ClientRow => ({
  client_id: client.clientId,
  data: json(client),
  created_at: client.createdAt.getTime(),
  updated_at: client.updatedAt.getTime()
})

export const toClient = (row: Read<ClientRow>): Client => ({
  ...parse<Client>(row.data),
  createdAt: at(row.created_at),
  updatedAt: at(row.updated_at)
})

/** `user_code` is lifted out of the payload so a device's code is found by index (FR-C7). */
export const artifactRow = (artifact: Artifact): ArtifactRow => ({
  kind: artifact.kind,
  id: artifact.id,
  client_id: artifact.clientId,
  account_id: artifact.accountId ?? null,
  grant_id: artifact.grantId ?? null,
  family_id: artifact.familyId ?? null,
  user_code: (artifact.payload.userCode as string | undefined) ?? null,
  payload: json(artifact.payload),
  consumed_at: artifact.consumedAt ? artifact.consumedAt.getTime() : null,
  expires_at: artifact.expiresAt.getTime()
})

export const toArtifact = (row: Read<ArtifactRow>): Artifact => ({
  id: row.id,
  kind: row.kind as ArtifactKind,
  clientId: row.client_id,
  ...(row.account_id && { accountId: row.account_id }),
  ...(row.grant_id && { grantId: row.grant_id }),
  ...(row.family_id && { familyId: row.family_id }),
  payload: parse<Record<string, unknown>>(row.payload),
  ...(row.consumed_at && { consumedAt: at(row.consumed_at) }),
  expiresAt: at(row.expires_at)
})

export const sessionRow = (session: Session): SessionRow => ({
  id: session.id,
  account_id: session.accountId,
  auth_time: session.authTime.getTime(),
  acr: session.acr ?? null,
  amr: session.amr ? json(session.amr) : null,
  idp: session.idp ?? null,
  upstream_session_id: session.upstreamSessionId ?? null,
  clients: json(session.clients),
  expires_at: session.expiresAt.getTime()
})

export const toSession = (row: Read<SessionRow>): Session => ({
  id: row.id,
  accountId: row.account_id,
  authTime: at(row.auth_time),
  ...(row.acr && { acr: row.acr }),
  ...(row.amr ? { amr: parse<string[]>(row.amr) } : {}),
  ...(row.idp && { idp: row.idp }),
  ...(row.upstream_session_id && { upstreamSessionId: row.upstream_session_id }),
  clients: parse<string[]>(row.clients),
  expiresAt: at(row.expires_at)
})

export const grantRow = (grant: Grant): GrantRow => ({
  id: grant.id,
  account_id: grant.accountId,
  client_id: grant.clientId,
  scopes: json(grant.scopes),
  claims: json(grant.claims),
  resources: json(grant.resources),
  created_at: grant.createdAt.getTime(),
  expires_at: grant.expiresAt ? grant.expiresAt.getTime() : null
})

export const toGrant = (row: Read<GrantRow>): Grant => ({
  id: row.id,
  accountId: row.account_id,
  clientId: row.client_id,
  scopes: parse<string[]>(row.scopes),
  claims: parse<string[]>(row.claims),
  resources: parse<Record<string, string[]>>(row.resources),
  createdAt: at(row.created_at),
  ...(row.expires_at && { expiresAt: at(row.expires_at) })
})

export const identityRow = (identity: LinkedIdentity): IdentityRow => ({
  provider: identity.provider,
  subject: identity.subject,
  account_id: identity.accountId,
  email: identity.email ?? null,
  claims: json(identity.claims),
  linked_at: identity.linkedAt.getTime()
})

export const toIdentity = (row: Read<IdentityRow>): LinkedIdentity => ({
  accountId: row.account_id,
  provider: row.provider,
  subject: row.subject,
  ...(row.email && { email: row.email }),
  claims: parse<Record<string, unknown>>(row.claims),
  linkedAt: at(row.linked_at)
})

export const credentialRow = (credential: Credential): CredentialRow => ({
  account_id: credential.accountId,
  username: credential.username,
  password_hash: credential.passwordHash,
  claims: json(credential.claims),
  totp_secret: credential.totp?.secret ?? null,
  totp_confirmed_at: credential.totp?.confirmedAt?.getTime() ?? null,
  recovery_codes: credential.recoveryCodes ? json(credential.recoveryCodes) : null,
  failed_attempts: credential.failedAttempts,
  locked_until: credential.lockedUntil?.getTime() ?? null,
  created_at: credential.createdAt.getTime(),
  updated_at: credential.updatedAt.getTime()
})

export const toCredential = (row: Read<CredentialRow>): Credential => ({
  accountId: row.account_id,
  username: row.username,
  passwordHash: row.password_hash,
  claims: parse<Record<string, unknown>>(row.claims),
  ...(row.totp_secret && {
    totp: { secret: row.totp_secret, ...(row.totp_confirmed_at && { confirmedAt: at(row.totp_confirmed_at) }) }
  }),
  ...(row.recovery_codes ? { recoveryCodes: parse<string[]>(row.recovery_codes) } : {}),
  failedAttempts: Number(row.failed_attempts),
  ...(row.locked_until && { lockedUntil: at(row.locked_until) }),
  createdAt: at(row.created_at),
  updatedAt: at(row.updated_at)
})

export const realmRow = (realm: Realm): RealmRow => ({
  id: realm.id,
  display_name: realm.displayName ?? null,
  enabled: realm.enabled ? 1 : 0,
  settings: json(realm.settings),
  created_at: realm.createdAt.getTime(),
  updated_at: realm.updatedAt.getTime()
})

export const toRealm = (row: Read<RealmRow>): Realm => ({
  id: row.id,
  ...(row.display_name && { displayName: row.display_name }),
  enabled: Boolean(Number(row.enabled)),
  settings: parse<Record<string, unknown>>(row.settings),
  createdAt: at(row.created_at),
  updatedAt: at(row.updated_at)
})
