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
  // FR-L8: an error without a description is still one, shown and dismissed by the same text in every binding.
  const flowError = () => oauth.errorDescription() ?? oauth.error()
  const {
    store,
    state,
    view: _view,
    ...actions
  } = createOAuthForm(
    {
      login: parameters => oauth.login(parameters),
      isAuthorized: () => oauth.isAuthorized(),
      errorDescription: () => flowError()
    },
    options
  )

  const snapshot = storeSignal(store, state)
  // read here, not through the controller, so this computed tracks it
  return { ...actions, view: computed(() => oauthFormView(snapshot(), flowError(), actions.maxLength)) }
}
