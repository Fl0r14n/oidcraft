// Types and pure rules only (ARCHITECTURE.md §8.1): the runtime stays in the root, or `instanceof OAuthError` breaks.
export {
  DEFAULT_MAX_LENGTH,
  type OAuthFieldError,
  type OAuthFieldErrors,
  oauthFieldError,
  oauthFieldErrors
} from '@oidcraft/core'

/** `logout` asks whether to end the session, when the request to do so could not prove who sent it. */
export type InteractionKind = 'login' | 'consent' | 'logout'

/** One RFC 9396 detail. Its fields are the host's to define, under the types it declared. */
export type InteractionAuthorizationDetail = { type: string } & Record<string, unknown>

/** What the authorization endpoint could not decide on its own, handed to the interaction app (FR-I1). */
export type InteractionRequest = {
  id: string
  kind: InteractionKind
  clientId: string
  scopes: string[]
  prompt: string[]
  loginHint: string | undefined
  acrValues: string[] | undefined
  uiLocales: string[] | undefined
  /** Seconds, when the client capped session age; with `prompt`, what an upstream leg must pass through (FR-F9). */
  maxAge: number | undefined
  /** Which upstreams this client may be brokered to, when it restricts them (FR-F2). */
  upstreamProviders: string[] | undefined
  /** Home-realm discovery's answer (FR-F4): `chosen` when one upstream is unambiguous, else `candidates` for the screen to offer. */
  upstream: { chosen: string | undefined; candidates: string[] } | undefined
  /** What the client asks to be allowed to do, for the consent screen to show (RFC 9396 §7, FR-C15). */
  authorizationDetails: InteractionAuthorizationDetail[] | undefined
  /**
   * Where the person returns. A consent screen must show its host, and say when it is this computer:
   * a document-registered client can claim any name it likes (MCP 2026-07-28).
   */
  redirectUri: string | undefined
  expiresAt: Date
}

/** The interaction app's answer. The core re-runs the authorization request against it (FR-I2). */
export type InteractionResult = {
  /**
   * `authTime`, when the person authenticated earlier: a brokered login passes the upstream's `auth_time` (FR-F6).
   * One older than the request's `max_age` allows answers the client `login_required` (FR-F9).
   */
  login?: { accountId: string; acr?: string; amr?: string[]; idp?: string; upstreamSessionId?: string; authTime?: Date }
  /** `authorizationDetails` must repeat every detail the request carried, all or nothing; declining some is `access_denied`. */
  consent?: { scopes: string[]; authorizationDetails?: InteractionAuthorizationDetail[] | undefined }
  error?: { error: 'access_denied' | 'login_required' | 'consent_required'; description?: string }
  /** The person confirmed a `logout` interaction. To decline, do not complete it: it expires and the session stays. */
  logout?: true
}

export type InteractionCompletion = { redirectTo: string; setCookie: string | undefined }
