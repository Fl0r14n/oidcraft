import { computed, inject, type Signal } from '@angular/core'
import { createOAuthForm, type OAuthFormController, type OAuthFormOptions } from '@oidcraft/client'
import { type OAuthFormView, oauthFormView } from '@oidcraft/core'
import { OAUTH } from './oauth'
import { storeSignal } from './signals'

export type OAuthForm = Omit<OAuthFormController, 'store' | 'state' | 'view'> & {
  view: Signal<OAuthFormView>
}

/** The resource-owner password form as signals; call it in an injection context. */
export const oauthForm = (options: OAuthFormOptions = {}): OAuthForm => {
  const oauth = inject(OAUTH)
  const {
    store,
    state,
    view: _view,
    ...actions
  } = createOAuthForm(
    {
      login: parameters => oauth.login(parameters),
      isAuthorized: () => oauth.isAuthorized(),
      errorDescription: () => oauth.errorDescription()
    },
    options
  )

  const snapshot = storeSignal(store, state)
  // read here, not through the controller, so this computed tracks it
  return { ...actions, view: computed(() => oauthFormView(snapshot(), oauth.errorDescription(), actions.maxLength)) }
}
