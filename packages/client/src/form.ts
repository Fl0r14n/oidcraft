import { DEFAULT_MAX_LENGTH, type OAuthFormState, type OAuthFormView, oauthFormView } from '@oidcraft/core'
import { createStore, type Subscribable } from './store'

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
