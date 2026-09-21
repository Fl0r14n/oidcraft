import { useMemo, useRef } from 'react'
import { createOAuthForm, type OAuthFormController, type OAuthFormOptions, type OAuthFormView, oauthFormView } from 'react-oauth-oidc/core'
import { useOAuthError, useStoreValue } from './hooks'
import { useOAuthInstance } from './provider'

/**
 * One view object rather than a property per field. A login form has two inputs, so splitting it
 * buys nothing and costs the interface being restated in every binding — which is how the same form
 * ended up written three times before.
 */
export type OAuthForm = Omit<OAuthFormController, 'store' | 'state' | 'view'> & {
  view: OAuthFormView
}

export type UseOAuthFormOptions = OAuthFormOptions

/**
 * The resource-owner password form. The rules and the submit lifecycle are `@oidcraft/core`'s and
 * `@oidcraft/client`'s, shared with the Vue and Angular bindings; this is the React wrapper.
 */
export const useOAuthForm = (options: UseOAuthFormOptions = {}): OAuthForm => {
  const oauth = useOAuthInstance()

  // Held in a ref because the options *seed* the form rather than bind to it: they are an object
  // literal at almost every call site, so depending on their identity would rebuild the controller
  // every render and throw away whatever the user had typed.
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
