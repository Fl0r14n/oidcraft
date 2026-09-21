import { createStore, type Subscribable } from './store'

export const DEFAULT_MAX_LENGTH = 128

/** A code, not a sentence: the wording belongs to whoever writes the markup, and to their locale. */
export type OAuthFieldError = 'required' | 'tooLong' | undefined

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

const fieldError = (value: string, maxLength: number): OAuthFieldError =>
  (!value && 'required') || (value.length > maxLength && 'tooLong') || undefined

/**
 * One pure derivation, the way `tokenState` is, so what a binding renders and what the controller
 * believes cannot drift. `flowError` is passed in rather than read, because each binding has to
 * observe it through its own reactive primitive for the view to update when it changes.
 */
export const oauthFormView = (state: OAuthFormState, flowError: string | undefined, maxLength = DEFAULT_MAX_LENGTH): OAuthFormView => {
  const username = fieldError(state.username, maxLength)
  const password = fieldError(state.password, maxLength)
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

/** What the form needs of an instance, and nothing more — which is what makes it testable. */
export interface OAuthFormHost {
  login: (parameters?: { username: string; password: string }) => Promise<unknown>
  isAuthorized: () => boolean
  errorDescription: () => string | undefined
}

export interface OAuthFormOptions {
  username?: string | undefined
  password?: string | undefined
  maxLength?: number | undefined
}

export interface OAuthFormController {
  store: Subscribable<OAuthFormState>
  state: () => OAuthFormState
  view: (flowError?: string) => OAuthFormView
  setUsername: (value: string) => void
  setPassword: (value: string) => void
  togglePasswordVisible: () => void
  dismissError: () => void
  reset: () => void
  submit: (event?: { preventDefault?: () => void }) => Promise<void>
  maxLength: number
}

/**
 * The resource-owner password form, without a framework and without markup.
 *
 * It exists once here because all three bindings had grown their own copy of the same rules — when a
 * field may show an error, what survives a rejected attempt, when a dismissed error comes back. A
 * binding wraps this in its reactive primitive and renders it; none of them re-decides any of it.
 *
 * Note the grant: OAuth 2.1 removed resource-owner password, so an `oidcraft` provider does not
 * advertise it. This is for the providers that still accept it.
 */
export const createOAuthForm = (
  oauth: OAuthFormHost,
  { username = '', password = '', maxLength = DEFAULT_MAX_LENGTH }: OAuthFormOptions = {}
): OAuthFormController => {
  const store = createStore<OAuthFormState>({
    username,
    password,
    submitted: false,
    submitting: false,
    passwordVisible: false,
    dismissed: undefined
  })

  const patch = (fields: Partial<OAuthFormState>) => store.setState({ ...store.getState(), ...fields })
  const state = () => store.getState()

  const reset = () => patch({ username: '', password: '', submitted: false })

  const submit = async (event?: { preventDefault?: () => void }) => {
    event?.preventDefault?.()
    patch({ submitted: true, dismissed: undefined })
    if (!oauthFormView(state(), undefined, maxLength).valid) return
    patch({ submitting: true })
    try {
      const { username: user, password: secret } = state()
      await oauth.login({ username: user, password: secret })
    } finally {
      patch({ submitting: false })
      if (oauth.isAuthorized()) {
        reset()
      } else {
        // the password goes, the username stays: a rejection is usually a typo in one of the two,
        // and retyping the address every time is the wrong thing to make someone do
        patch({ password: '', submitted: false })
      }
    }
  }

  return {
    store,
    state,
    view: (flowError = oauth.errorDescription()) => oauthFormView(state(), flowError, maxLength),
    setUsername: value => patch({ username: value }),
    setPassword: value => patch({ password: value }),
    togglePasswordVisible: () => patch({ passwordVisible: !state().passwordVisible }),
    dismissError: () => patch({ dismissed: oauth.errorDescription() }),
    reset,
    submit,
    maxLength
  }
}
