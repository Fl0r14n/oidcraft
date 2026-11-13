import type { Artifact, ArtifactKind, ArtifactStore } from '@oidcraft/adapter'
import type { AuthorizationRequest, ResponseTarget } from './authorize/authorization'
import type { CibaPayload } from './authorize/ciba'
import type { RequestedClaims } from './authorize/claims'
import type { Answer } from './authorize/decoupled'
import type { DevicePayload } from './authorize/device'
import type { Handoff } from './broker/types'

export type Confirmation = { jkt?: string; 'x5t#S256'?: string }

/** A sign-in as an `offline_access` refresh token carries it, to outlive the session (OIDC Core §11). */
export type SignIn = { id: string; accountId: string; authTime: number; acr?: string; amr?: string[]; idp?: string }

export type CodePayload = {
  redirectUri: string
  codeChallenge: string | undefined
  scopes: string[]
  sessionId: string
  nonce?: string
  authorizationDetails?: unknown[]
  resources?: string[]
  dpopJkt?: string
  claims?: RequestedClaims
}

export type AccessTokenPayload = {
  iat: number
  scopes: string[]
  sessionId?: string
  subject?: string
  authorizationDetails?: unknown[]
  act?: { client_id: string }
  resource?: string
  aud?: string
  cnf?: Confirmation
  format?: 'jwt'
  /** Released at UserInfo beyond the scopes, as consented (FR-C22). */
  claims?: string[]
}

export type RefreshTokenPayload = {
  iat: number
  scopes: string[]
  sessionId: string
  signIn?: SignIn
  sessionBound?: true
  /** Epoch seconds: the family's absolute end, which no rotation moves (FR-T6). */
  familyExpiresAt: number
  resources?: string[]
  cnf?: Confirmation
  claims?: RequestedClaims
}

export type DeviceLogin = { userCode: string; scopes: string[] }

/** `browser` is the hash of the binding cookie of the browser sent to it (FR-I2). */
export type InteractionPayload = { browser: string } & (
  | {
      interactionKind: 'login' | 'consent'
      request: AuthorizationRequest
      upstream?: { chosen: string | undefined; candidates: string[] }
    }
  | { interactionKind: 'login'; device: DeviceLogin }
  | { interactionKind: 'logout'; sessionId: string; state?: string; target?: string }
)

type Empty = Record<string, never>

/** What each kind of artifact carries. Nothing but the provider writes a payload, so its own type is the whole of its validation. */
export type Payloads = {
  interaction: InteractionPayload
  broker_handoff: Omit<Handoff, 'expiresAt'>
  /** Where the browser goes once the upstream has signed it out too (FR-F8). */
  broker_logout: { destination?: string }
  /** An upstream ID token kept as the `id_token_hint` of its logout, for a provider that propagates it (FR-F8). */
  upstream_id_token: { idToken: string }
  authorization_code: CodePayload
  access_token: AccessTokenPayload
  refresh_token: RefreshTokenPayload
  device_code: DevicePayload
  /** The person's answer to a device request, under its user code. */
  user_code: Answer
  pushed_authorization_request: { params: string }
  /** The request, and the person's answer beside it under `<auth_req_id>:answer`. */
  backchannel_authentication_request: CibaPayload | Answer
  registration_access_token: Empty
  authorization_details_consent: Empty
  dpop_nonce: Empty
  authorization_response: { target: ResponseTarget; values: Record<string, string> }
  user_code_attempts: { failures: number }
  /** Failed sign-ins at one account from one address, written by `./accounts`; a lock outlives the generation it ended (G-9). */
  sign_in_attempts: { generation: string; lockedUntil?: number }
  password_reset: Empty
  /** Written before a family's tokens are deleted, so a token written into it after the sweep is caught (FR-T3). */
  revoked_family: Empty
}

/** One record per kind, so a union of kinds narrows on `kind`. */
export type Stored<K extends ArtifactKind = ArtifactKind> = K extends ArtifactKind
  ? Omit<Artifact, 'kind' | 'payload'> & { kind: K; payload: Payloads[K] }
  : never

export const readArtifact = async <K extends ArtifactKind>(store: ArtifactStore, kind: K, id: string) =>
  (await store.find(kind, id)) as Stored<K> | undefined

export const readByUserCode = async (store: ArtifactStore, userCode: string) =>
  (await store.findByUserCode?.(userCode)) as Stored<'device_code'> | undefined

export const writeArtifact = <K extends ArtifactKind>(store: ArtifactStore, artifact: Stored<K>) =>
  store.upsert(artifact as unknown as Artifact)
