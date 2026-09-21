import { useMemo, useRef } from 'react'
import { createOAuthForm, type OAuthFieldError, type OAuthFormOptions, oauthFormView } from 'react-oauth-oidc/core'
import { useOAuthError, useStoreValue } from './hooks'
import { useOAuthInstance } from './provider'

export interface OAuthFormField {
  value: string
  error: OAuthFieldError
  /** gate error display on this: a pristine form should not shout about empty required fields */
  showError: boolean
  onChange: (value: string) => void
}

export interface OAuthForm {
  username: OAuthFormField
  password: OAuthFormField
  valid: boolean
  submitted: boolean
  submitting: boolean
  error: string | undefined
  dismissError: () => void
  passwordVisible: boolean
  togglePasswordVisible: () => void
  submit: (event?: { preventDefault?: () => void }) => Promise<void>
  reset: () => void
  maxLength: number
}

export type UseOAuthFormOptions = OAuthFormOptions

/**
 * The resource-owner password form. The rules — when a field may show an error, what survives a
 * rejected attempt, when a dismissed error comes back — are `@oidcraft/client`'s and are shared with
 * the Vue and Angular bindings; this is the React wrapper and nothing else.
 */
export const useOAuthForm = (options: UseOAuthFormOptions = {}): OAuthForm => {
  const oauth = useOAuthInstance()

  // Held in a ref because the options *seed* the form rather than bind to it: they are an object
  // literal at almost every call site, so depending on their identity would rebuild the controller
  // every render and throw away whatever the user had typed. This is what `useState(username)` did
  // before, said out loud.
  const seed = useRef(options)

  const controller = useMemo(
    () =>
      createOAuthForm(
        {
          login: parameters => oauth.login(parameters),
          isAuthorized: oauth.isAuthorized,
          errorDescription: oauth.errorDescription
        },
        seed.current
      ),
    [oauth]
  )

  const state = useStoreValue(controller.store, snapshot => snapshot)
  const flowError = useOAuthError()
  const view = oauthFormView(state, flowError, controller.maxLength)

  return {
    username: { ...view.username, onChange: controller.setUsername },
    password: { ...view.password, onChange: controller.setPassword },
    valid: view.valid,
    submitted: view.submitted,
    submitting: view.submitting,
    error: view.error,
    dismissError: controller.dismissError,
    passwordVisible: view.passwordVisible,
    togglePasswordVisible: controller.togglePasswordVisible,
    submit: controller.submit,
    reset: controller.reset,
    maxLength: controller.maxLength
  }
}
