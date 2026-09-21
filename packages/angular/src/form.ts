import { computed, inject, type Signal } from '@angular/core'
import { createOAuthForm, type OAuthFieldError, type OAuthFormOptions, oauthFormView } from '@oidcraft/client'
import { OAUTH } from './oauth'
import { storeSignal } from './signals'

export interface OAuthFormField {
  value: Signal<string>
  error: Signal<OAuthFieldError>
  /** gate the display on this: a pristine form should not shout about empty required fields */
  showError: Signal<boolean>
  set: (value: string) => void
}

export interface OAuthForm {
  username: OAuthFormField
  password: OAuthFormField
  valid: Signal<boolean>
  submitted: Signal<boolean>
  submitting: Signal<boolean>
  error: Signal<string | undefined>
  dismissError: () => void
  passwordVisible: Signal<boolean>
  togglePasswordVisible: () => void
  submit: (event?: { preventDefault?: () => void }) => Promise<void>
  reset: () => void
  maxLength: number
}

/**
 * The resource-owner password form as signals. The rules — when a field may show an error, what
 * survives a rejected attempt, when a dismissed error comes back — are `@oidcraft/client`'s and are
 * shared with the Vue and React bindings; this is the reactive wrapper and nothing else.
 *
 * Call it in an injection context. v8 shipped this as a Material component under
 * `ngx-oauth/component`; see the README for why that entry is gone.
 */
export const oauthForm = (options: OAuthFormOptions = {}): OAuthForm => {
  const oauth = inject(OAUTH)
  const controller = createOAuthForm(
    {
      login: parameters => oauth.login(parameters),
      isAuthorized: () => oauth.isAuthorized(),
      errorDescription: () => oauth.errorDescription()
    },
    options
  )

  const state = storeSignal(controller.store, controller.state)
  // the flow error is read here rather than inside the controller so this computed tracks it
  const view = computed(() => oauthFormView(state(), oauth.errorDescription(), controller.maxLength))

  const field = (name: 'username' | 'password'): OAuthFormField => ({
    value: computed(() => view()[name].value),
    error: computed(() => view()[name].error),
    showError: computed(() => view()[name].showError),
    set: name === 'username' ? controller.setUsername : controller.setPassword
  })

  return {
    username: field('username'),
    password: field('password'),
    valid: computed(() => view().valid),
    submitted: computed(() => view().submitted),
    submitting: computed(() => view().submitting),
    error: computed(() => view().error),
    dismissError: controller.dismissError,
    passwordVisible: computed(() => view().passwordVisible),
    togglePasswordVisible: controller.togglePasswordVisible,
    submit: controller.submit,
    reset: controller.reset,
    maxLength: controller.maxLength
  }
}
