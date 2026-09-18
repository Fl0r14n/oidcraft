import { useMemo, useState } from 'react'
import { useOAuthActions, useOAuthError } from './hooks'
import { useOAuthInstance } from './provider'

export const DEFAULT_MAX_LENGTH = 128

export type OAuthFieldError = 'required' | 'tooLong' | undefined

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

export interface UseOAuthFormOptions {
  username?: string | undefined
  password?: string | undefined
  maxLength?: number | undefined
}

const fieldError = (value: string, maxLength: number): OAuthFieldError =>
  (!value && 'required') || (value.length > maxLength && 'tooLong') || undefined

export const useOAuthForm = ({ username = '', password = '', maxLength = DEFAULT_MAX_LENGTH }: UseOAuthFormOptions = {}): OAuthForm => {
  const { login } = useOAuthActions()
  const { isAuthorized } = useOAuthInstance()
  const flowError = useOAuthError()

  const [model, setModel] = useState({ username, password })
  const [submitted, setSubmitted] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [passwordVisible, setPasswordVisible] = useState(false)
  const [dismissedError, setDismissedError] = useState<string | undefined>(undefined)

  const errors = useMemo(
    () => ({
      username: fieldError(model.username, maxLength),
      password: fieldError(model.password, maxLength)
    }),
    [model, maxLength]
  )

  const valid = !errors.username && !errors.password

  const reset = () => {
    setModel({ username: '', password: '' })
    setSubmitted(false)
  }

  const submit = async (event?: { preventDefault?: () => void }) => {
    event?.preventDefault?.()
    setSubmitted(true)
    setDismissedError(undefined)
    if (!valid) return
    setSubmitting(true)
    try {
      await login(model)
    } finally {
      setSubmitting(false)
      if (isAuthorized()) {
        reset()
      } else {
        setModel(m => ({ ...m, password: '' }))
        setSubmitted(false)
      }
    }
  }

  return {
    username: {
      value: model.username,
      error: errors.username,
      showError: submitted && !!errors.username,
      onChange: value => setModel(m => ({ ...m, username: value }))
    },
    password: {
      value: model.password,
      error: errors.password,
      showError: submitted && !!errors.password,
      onChange: value => setModel(m => ({ ...m, password: value }))
    },
    valid,
    submitted,
    submitting,
    error: (flowError !== dismissedError && flowError) || undefined,
    dismissError: () => setDismissedError(flowError),
    passwordVisible,
    togglePasswordVisible: () => setPasswordVisible(visible => !visible),
    submit,
    reset,
    maxLength
  }
}
