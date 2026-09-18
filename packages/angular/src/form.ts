import { computed, inject, type Signal, signal } from '@angular/core'
import type { NgxOAuth } from './oauth'
import { OAUTH } from './oauth'

export const DEFAULT_MAX_LENGTH = 128

/** A code, not a sentence: the wording belongs to whoever writes the markup, and to their locale. */
export type OAuthFieldError = 'required' | 'tooLong' | undefined

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

export interface OAuthFormOptions {
  username?: string | undefined
  password?: string | undefined
  maxLength?: number | undefined
}

const fieldError = (value: string, maxLength: number): OAuthFieldError =>
  (!value && 'required') || (value.length > maxLength && 'tooLong') || undefined

/**
 * The resource-owner password form, without the markup.
 *
 * v8 shipped this as a Material component under `ngx-oauth/component`. That entry is gone, because a
 * published Angular *component* has to be compiled by `ngc` into partial form, and `ngc` requires a
 * TypeScript this workspace does not use (ARCHITECTURE.md §8.4). What the component was actually
 * worth is here instead: the validation, the submit lifecycle, and the rules about when an error is
 * allowed to show — none of which are Material's, or anyone's markup.
 *
 * Call it in an injection context. `react-oauth-oidc` ships the same thing as `useOAuthForm`.
 */
export const oauthForm = ({ username = '', password = '', maxLength = DEFAULT_MAX_LENGTH }: OAuthFormOptions = {}): OAuthForm => {
  const oauth: NgxOAuth = inject(OAUTH)

  const model = signal({ username, password })
  const submitted = signal(false)
  const submitting = signal(false)
  const passwordVisible = signal(false)
  const dismissed = signal<string | undefined>(undefined)

  const errors = computed(() => ({
    username: fieldError(model().username, maxLength),
    password: fieldError(model().password, maxLength)
  }))
  const valid = computed(() => !errors().username && !errors().password)

  const field = (name: 'username' | 'password'): OAuthFormField => ({
    value: computed(() => model()[name]),
    error: computed(() => errors()[name]),
    showError: computed(() => submitted() && !!errors()[name]),
    set: value => model.update(current => ({ ...current, [name]: value }))
  })

  const reset = () => {
    model.set({ username: '', password: '' })
    submitted.set(false)
  }

  const submit = async (event?: { preventDefault?: () => void }) => {
    event?.preventDefault?.()
    submitted.set(true)
    dismissed.set(undefined)
    if (!valid()) return
    submitting.set(true)
    try {
      await oauth.login(model())
    } finally {
      submitting.set(false)
      if (oauth.isAuthorized()) {
        reset()
      } else {
        // the password goes, the username stays: a rejected attempt is usually a typo in one of them,
        // and retyping the address every time is the wrong thing to make someone do
        model.update(current => ({ ...current, password: '' }))
        submitted.set(false)
      }
    }
  }

  return {
    username: field('username'),
    password: field('password'),
    valid,
    submitted,
    submitting,
    // the flow's own error, until it is dismissed — and again the moment a different one arrives
    error: computed(() => {
      const current = oauth.errorDescription()
      return (current !== dismissed() && current) || undefined
    }),
    dismissError: () => dismissed.set(oauth.errorDescription()),
    passwordVisible,
    togglePasswordVisible: () => passwordVisible.update(visible => !visible),
    submit,
    reset,
    maxLength
  }
}
