import type { Artifact, ArtifactKind, Client, Credential, Grant, LinkedIdentity, Passkey, Realm, Session } from '@oidcraft/adapter'

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
  last_used_at: number | null
  secret_hash: string | null
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
  password_hash: string | null
  claims: string
  totp_secret: string | null
  totp_confirmed_at: number | null
  recovery_codes: string | null
  failed_attempts: number
  locked_until: number | null
  created_at: number
  updated_at: number
}

export type PasskeyRow = {
  credential_id: string
  account_id: string
  public_key: string
  algorithm: number
  counter: number
  transports: string
  name: string
  created_at: number
  last_used_at: number | null
}

/** A row as read back: Postgres returns a `bigint` as a string. */
export type Read<T> = { [K in keyof T]: T[K] extends number ? number | string : T[K] extends number | null ? number | string | null : T[K] }

/** MySQL's replay key: a claimed value is often a client's jti, whose length the client chooses, and a key's is fixed (NFR-S5). */
export const replayDigest = async (value: string) =>
  btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)))))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')

export const json = (value: unknown) => JSON.stringify(value)
export const parse = <T>(value: string) => JSON.parse(value) as T

export const clientRow = (client: Client): ClientRow => ({
  client_id: client.clientId,
  data: json(client),
  created_at: client.createdAt,
  updated_at: client.updatedAt
})

export const toClient = (row: Read<ClientRow>): Client => ({
  ...parse<Client>(row.data),
  createdAt: Number(row.created_at),
  updatedAt: Number(row.updated_at)
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
  consumed_at: artifact.consumedAt ?? null,
  expires_at: artifact.expiresAt
})

export const toArtifact = (row: Read<ArtifactRow>): Artifact => ({
  id: row.id,
  kind: row.kind as ArtifactKind,
  clientId: row.client_id,
  ...(row.account_id && { accountId: row.account_id }),
  ...(row.grant_id && { grantId: row.grant_id }),
  ...(row.family_id && { familyId: row.family_id }),
  payload: parse<Record<string, unknown>>(row.payload),
  ...(row.consumed_at && { consumedAt: Number(row.consumed_at) }),
  expiresAt: Number(row.expires_at)
})

export const sessionRow = (session: Session): SessionRow => ({
  id: session.id,
  account_id: session.accountId,
  auth_time: session.authTime,
  acr: session.acr ?? null,
  amr: session.amr ? json(session.amr) : null,
  idp: session.idp ?? null,
  upstream_session_id: session.upstreamSessionId ?? null,
  clients: json(session.clients),
  expires_at: session.expiresAt,
  last_used_at: session.lastUsedAt ?? null,
  secret_hash: session.secretHash ?? null
})

export const toSession = (row: Read<SessionRow>): Session => ({
  id: row.id,
  accountId: row.account_id,
  authTime: Number(row.auth_time),
  ...(row.acr && { acr: row.acr }),
  ...(row.amr ? { amr: parse<string[]>(row.amr) } : {}),
  ...(row.idp && { idp: row.idp }),
  ...(row.upstream_session_id && { upstreamSessionId: row.upstream_session_id }),
  clients: parse<string[]>(row.clients),
  expiresAt: Number(row.expires_at),
  ...(row.last_used_at !== null && row.last_used_at !== undefined && { lastUsedAt: Number(row.last_used_at) }),
  ...(row.secret_hash && { secretHash: row.secret_hash })
})

export const grantRow = (grant: Grant): GrantRow => ({
  id: grant.id,
  account_id: grant.accountId,
  client_id: grant.clientId,
  scopes: json(grant.scopes),
  claims: json(grant.claims),
  resources: json(grant.resources),
  created_at: grant.createdAt,
  expires_at: grant.expiresAt ?? null
})

export const toGrant = (row: Read<GrantRow>): Grant => ({
  id: row.id,
  accountId: row.account_id,
  clientId: row.client_id,
  scopes: parse<string[]>(row.scopes),
  claims: parse<string[]>(row.claims),
  resources: parse<Record<string, string[]>>(row.resources),
  createdAt: Number(row.created_at),
  ...(row.expires_at && { expiresAt: Number(row.expires_at) })
})

export const identityRow = (identity: LinkedIdentity): IdentityRow => ({
  provider: identity.upstream,
  subject: identity.subject,
  account_id: identity.accountId,
  email: identity.email ?? null,
  claims: json(identity.claims),
  linked_at: identity.createdAt
})

export const toIdentity = (row: Read<IdentityRow>): LinkedIdentity => ({
  accountId: row.account_id,
  upstream: row.provider,
  subject: row.subject,
  ...(row.email && { email: row.email }),
  claims: parse<Record<string, unknown>>(row.claims),
  createdAt: Number(row.linked_at)
})

export const credentialRow = (credential: Credential): CredentialRow => ({
  account_id: credential.accountId,
  username: credential.username,
  password_hash: credential.passwordHash ?? null,
  claims: json(credential.claims),
  totp_secret: credential.totp?.secret ?? null,
  totp_confirmed_at: credential.totp?.confirmedAt ?? null,
  recovery_codes: credential.recoveryCodes ? json(credential.recoveryCodes) : null,
  failed_attempts: credential.failedAttempts,
  locked_until: credential.lock?.expiresAt ?? null,
  created_at: credential.createdAt,
  updated_at: credential.updatedAt
})

export const toCredential = (row: Read<CredentialRow>): Credential => ({
  accountId: row.account_id,
  username: row.username,
  ...(row.password_hash && { passwordHash: row.password_hash }),
  claims: parse<Record<string, unknown>>(row.claims),
  ...(row.totp_secret && {
    totp: { secret: row.totp_secret, ...(row.totp_confirmed_at && { confirmedAt: Number(row.totp_confirmed_at) }) }
  }),
  ...(row.recovery_codes ? { recoveryCodes: parse<string[]>(row.recovery_codes) } : {}),
  failedAttempts: Number(row.failed_attempts),
  ...(row.locked_until && { lock: { expiresAt: Number(row.locked_until) } }),
  createdAt: Number(row.created_at),
  updatedAt: Number(row.updated_at)
})

export const passkeyRow = (passkey: Passkey): PasskeyRow => ({
  credential_id: passkey.credentialId,
  account_id: passkey.accountId,
  public_key: passkey.publicKey,
  algorithm: passkey.algorithm,
  counter: passkey.counter,
  transports: json(passkey.transports),
  name: passkey.name,
  created_at: passkey.createdAt,
  last_used_at: passkey.lastUsedAt ?? null
})

export const toPasskey = (row: Read<PasskeyRow>): Passkey => ({
  credentialId: row.credential_id,
  accountId: row.account_id,
  publicKey: row.public_key,
  algorithm: Number(row.algorithm),
  counter: Number(row.counter),
  transports: parse<string[]>(row.transports),
  name: row.name,
  createdAt: Number(row.created_at),
  ...(row.last_used_at !== null && { lastUsedAt: Number(row.last_used_at) })
})

export const realmRow = (realm: Realm): RealmRow => ({
  id: realm.id,
  display_name: realm.displayName ?? null,
  enabled: realm.enabled ? 1 : 0,
  settings: json(realm.settings),
  created_at: realm.createdAt,
  updated_at: realm.updatedAt
})

export const toRealm = (row: Read<RealmRow>): Realm => ({
  id: row.id,
  ...(row.display_name && { displayName: row.display_name }),
  enabled: Boolean(Number(row.enabled)),
  settings: parse<Record<string, unknown>>(row.settings),
  createdAt: Number(row.created_at),
  updatedAt: Number(row.updated_at)
})

/** What `update` takes: each field optional, and `undefined` to clear it. */
type Fields<T> = { [Field in keyof T]?: T[Field] | undefined }

/** The columns `fields` set, encoded by the full row's own mapper; a field the map leaves out is a key and never written. */
const changed = <T extends object, R>(
  toRow: (value: T) => R,
  blank: T,
  columns: Partial<Record<keyof T, (keyof R)[]>>,
  fields: Fields<T>
) => {
  const row = toRow({ ...blank, ...fields } as T)
  const set: Partial<R> = {}
  for (const field of Object.keys(fields) as (keyof T)[]) for (const column of columns[field] ?? []) set[column] = row[column]
  return set
}

const EPOCH = 0

export const sessionFields = (fields: Fields<Session>) =>
  changed(
    sessionRow,
    { id: '', accountId: '', authTime: EPOCH, clients: [], expiresAt: EPOCH },
    {
      accountId: ['account_id'],
      authTime: ['auth_time'],
      acr: ['acr'],
      amr: ['amr'],
      idp: ['idp'],
      upstreamSessionId: ['upstream_session_id'],
      expiresAt: ['expires_at'],
      lastUsedAt: ['last_used_at'],
      secretHash: ['secret_hash']
    },
    fields
  )

export const credentialFields = (fields: Fields<Credential>) =>
  changed(
    credentialRow,
    { accountId: '', username: '', claims: {}, failedAttempts: 0, createdAt: EPOCH, updatedAt: EPOCH },
    {
      passwordHash: ['password_hash'],
      claims: ['claims'],
      totp: ['totp_secret', 'totp_confirmed_at'],
      recoveryCodes: ['recovery_codes'],
      failedAttempts: ['failed_attempts'],
      lock: ['locked_until'],
      createdAt: ['created_at'],
      updatedAt: ['updated_at']
    },
    fields
  )

export const passkeyFields = (fields: Fields<Passkey>) =>
  changed(
    passkeyRow,
    { credentialId: '', accountId: '', publicKey: '', algorithm: 0, counter: 0, transports: [], name: '', createdAt: EPOCH },
    {
      publicKey: ['public_key'],
      algorithm: ['algorithm'],
      counter: ['counter'],
      transports: ['transports'],
      name: ['name'],
      createdAt: ['created_at'],
      lastUsedAt: ['last_used_at']
    },
    fields
  )
