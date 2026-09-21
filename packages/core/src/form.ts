/**
 * The credential form's rules, and nothing else.
 *
 * These are here rather than in `@oidcraft/client` because both halves of the protocol need them and
 * only one of them has a browser. A relying party collecting a password for the resource-owner grant
 * and an authorization server asking for its own password on its own login page are the same two
 * fields with the same validation; what differs is where the credentials go, which is the caller's
 * business and not this module's.
 *
 * Everything here is pure — no state, no storage, no markup — so a server-rendered screen can use it
 * as readily as a reactive binding (FR-A1, FR-I1).
 */

export const DEFAULT_MAX_LENGTH = 128

/** A code, not a sentence: the wording belongs to whoever renders it, and to their locale (FR-I6). */
export type OAuthFieldError = 'required' | 'tooLong' | undefined

export const oauthFieldError = (value: string | null | undefined, maxLength = DEFAULT_MAX_LENGTH): OAuthFieldError =>
  (!value && 'required') || ((value as string).length > maxLength && 'tooLong') || undefined

export interface OAuthFieldErrors {
  username: OAuthFieldError
  password: OAuthFieldError
}

export const oauthFieldErrors = (
  username: string | null | undefined,
  password: string | null | undefined,
  maxLength = DEFAULT_MAX_LENGTH
): OAuthFieldErrors => ({
  username: oauthFieldError(username, maxLength),
  password: oauthFieldError(password, maxLength)
})

export interface OAuthFormState {
  username: string
  password: string
  submitted: boolean
  submitting: boolean
  passwordVisible: boolean
  /** the flow error the user has already dismissed, so a *different* one still shows */
  dismissed: string | undefined
}

export interface OAuthFormFieldView {
  value: string
  error: OAuthFieldError
  /** gate the display on this: a pristine form should not shout about empty required fields */
  showError: boolean
}

export interface OAuthFormView {
  username: OAuthFormFieldView
  password: OAuthFormFieldView
  valid: boolean
  submitted: boolean
  submitting: boolean
  passwordVisible: boolean
  error: string | undefined
  maxLength: number
}

/**
 * One pure derivation, the way `tokenState` is, so what a binding renders and what a controller
 * believes cannot drift. `flowError` is passed in rather than read, because a reactive caller has to
 * observe it through its own primitive for the view to update when it changes.
 */
export const oauthFormView = (state: OAuthFormState, flowError: string | undefined, maxLength = DEFAULT_MAX_LENGTH): OAuthFormView => {
  const { username, password } = oauthFieldErrors(state.username, state.password, maxLength)
  return {
    username: { value: state.username, error: username, showError: state.submitted && !!username },
    password: { value: state.password, error: password, showError: state.submitted && !!password },
    valid: !username && !password,
    submitted: state.submitted,
    submitting: state.submitting,
    passwordVisible: state.passwordVisible,
    error: (flowError !== state.dismissed && flowError) || undefined,
    maxLength
  }
}
