/**
 * The interaction contract: what a host replacing the reference screens reads and answers. The
 * runtime that serves it is `provider.interactions`, because it shares the root's errors and
 * session code and a second bundled copy would break `instanceof OAuthError`.
 *
 * The credential form's rules travel with the interaction contract, because a host replacing these
 * screens has to validate the same things the screens do. They are pure and carry no UI peer, which
 * is what lets this entry hold them (ARCHITECTURE.md §8.1); rendering stays the host's (FR-I1).
 */
export {
  DEFAULT_MAX_LENGTH,
  type OAuthFieldError,
  type OAuthFieldErrors,
  oauthFieldError,
  oauthFieldErrors
} from '@oidcraft/core'

export type InteractionKind = 'login' | 'consent'

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
  /**
   * Seconds, when the client capped session age. Together with `prompt` this is what an upstream
   * leg must pass through rather than satisfy from whatever session it already holds (FR-F9).
   */
  maxAge: number | undefined
  /** Which upstreams this client may be brokered to, when it restricts them (FR-F2). */
  upstreamProviders: string[] | undefined
  /**
   * Home-realm discovery's answer (FR-F4). `chosen` is set when one upstream is unambiguous;
   * otherwise `candidates` is what the screen offers, because guessing would sign the user in
   * somewhere they did not ask for.
   */
  upstream: { chosen: string | undefined; candidates: string[] } | undefined
  expiresAt: Date
}

/** The interaction app's answer. The core re-runs the authorization request against it (FR-I2). */
export type InteractionResult = {
  login?: { accountId: string; acr?: string; amr?: string[]; idp?: string; upstreamSessionId?: string }
  consent?: { scopes: string[] }
  error?: { error: 'access_denied' | 'login_required' | 'consent_required'; description?: string }
}

export type InteractionCompletion = { redirectTo: string; setCookie: string | undefined }
