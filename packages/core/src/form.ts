// Pure — no state, storage or markup — so a server-rendered screen shares it with a reactive binding (FR-A1, FR-I1).

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
  /** the flow error the user dismissed, so a different one still shows */
  dismissed: string | undefined
}

export interface OAuthFormFieldView {
  value: string
  error: OAuthFieldError
  /** false until the form is submitted, so a pristine form shows no error */
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

/** What a binding renders; `flowError` is passed in so a reactive caller observes it through its own primitive. */
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
