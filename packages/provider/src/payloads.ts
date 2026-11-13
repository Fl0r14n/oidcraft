import type { Artifact, ArtifactKind, ArtifactStore } from '@oidcraft/adapter'
import type { AuthorizationRequest, ResponseTarget } from './authorize/authorization'
import type { CibaPayload } from './authorize/ciba'
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
}

export type DeviceLogin = { userCode: string; scopes: string[] }

export type InteractionPayload =
  | {
      interactionKind: 'login' | 'consent'
      request: AuthorizationRequest
      upstream?: { chosen: string | undefined; candidates: string[] }
    }
  | { interactionKind: 'login'; device: DeviceLogin }
  | { interactionKind: 'logout'; sessionId: string; state?: string }

type Empty = Record<string, never>

/** What each kind of artifact carries. Nothing but the provider writes a payload, so its own type is the whole of its validation. */
export type Payloads = {
  interaction: InteractionPayload
  broker_handoff: Omit<Handoff, 'expiresAt'>
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
  password_reset: Empty
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
