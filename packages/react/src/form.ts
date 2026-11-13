import { createOAuthForm, type OAuthFormController, type OAuthFormOptions, type OAuthFormView, oauthFormView } from '@oidcraft/react/core'
import { useMemo, useRef } from 'react'
import { useOAuthError, useStoreValue } from './hooks'
import { useOAuthInstance } from './provider'

export type OAuthForm = Omit<OAuthFormController, 'store' | 'state' | 'view'> & {
  view: OAuthFormView
}

export type UseOAuthFormOptions = OAuthFormOptions

/** The resource-owner password form. */
export const useOAuthForm = (options: UseOAuthFormOptions = {}): OAuthForm => {
  const oauth = useOAuthInstance()

  // the options seed the form, not bind to it: depending on a literal's identity would rebuild it every render
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

  const snapshot = useStoreValue(controller.store, state => state)
  const flowError = useOAuthError()
  const { store, state, view, ...actions } = controller

  return { ...actions, view: oauthFormView(snapshot, flowError, controller.maxLength) }
}
