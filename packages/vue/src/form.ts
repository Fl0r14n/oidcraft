import { createOAuthForm, type OAuthFieldError, type OAuthFormOptions, oauthFormView } from '@oidcraft/client'
import { type ComputedRef, computed, type WritableComputedRef } from 'vue'
import { getActiveOAuth } from './module'
import { storeRef } from './refs'

export interface OAuthFieldErrors {
  username: OAuthFieldError
  password: OAuthFieldError
}

/**
 * Flat, where the React and Angular bindings nest a field object. Vue unwraps a ref in a template
 * only when it is a *top-level* binding, so a nested `form.username.value` renders the ref rather
 * than the string and `v-model` binds the wrong thing. Destructure this and `v-model="username"`
 * works, which is the whole point.
 */
export interface OAuthForm {
  username: WritableComputedRef<string>
  password: WritableComputedRef<string>
  errors: ComputedRef<OAuthFieldErrors>
  /** which of `errors` may be shown yet: a pristine form should not shout about empty fields */
  showErrors: ComputedRef<{ username: boolean; password: boolean }>
  valid: ComputedRef<boolean>
  submitted: ComputedRef<boolean>
  submitting: ComputedRef<boolean>
  error: ComputedRef<string | undefined>
  dismissError: () => void
  passwordVisible: ComputedRef<boolean>
  togglePasswordVisible: () => void
  submit: (event?: { preventDefault?: () => void }) => Promise<void>
  reset: () => void
  maxLength: number
}

/**
 * The resource-owner password form. The rules — when a field may show an error, what survives a
 * rejected attempt, when a dismissed error comes back — are `@oidcraft/client`'s and are shared with
 * the React and Angular bindings; this is the Vue wrapper and nothing else.
 *
 * Call it inside a component setup or another effect scope: it subscribes, and the scope is what
 * unsubscribes. Note the grant — OAuth 2.1 removed resource-owner password, so an `oidcraft`
 * provider does not advertise it; this is for the providers that still accept it.
 */
export const useOAuthForm = (options: OAuthFormOptions = {}): OAuthForm => {
  const oauth = getActiveOAuth()
  const controller = createOAuthForm(
    {
      login: parameters => oauth.login(parameters),
      isAuthorized: () => oauth.isAuthorized.value,
      errorDescription: () => oauth.errorDescription.value
    },
    options
  )

  const state = storeRef(controller.store, controller.state)
  // the flow error is read here rather than inside the controller so this computed tracks it
  const view = computed(() => oauthFormView(state.value, oauth.errorDescription.value, controller.maxLength))

  const field = (name: 'username' | 'password') =>
    computed({
      get: () => view.value[name].value,
      set: name === 'username' ? controller.setUsername : controller.setPassword
    })

  return {
    username: field('username'),
    password: field('password'),
    errors: computed(() => ({ username: view.value.username.error, password: view.value.password.error })),
    showErrors: computed(() => ({ username: view.value.username.showError, password: view.value.password.showError })),
    valid: computed(() => view.value.valid),
    submitted: computed(() => view.value.submitted),
    submitting: computed(() => view.value.submitting),
    error: computed(() => view.value.error),
    dismissError: controller.dismissError,
    passwordVisible: computed(() => view.value.passwordVisible),
    togglePasswordVisible: controller.togglePasswordVisible,
    submit: controller.submit,
    reset: controller.reset,
    maxLength: controller.maxLength
  }
}
