import { createOAuthForm, type OAuthFormController, type OAuthFormOptions } from '@oidcraft/client'
import { type OAuthFormView, oauthFormView } from '@oidcraft/core'
import { type ComputedRef, computed, type WritableComputedRef } from 'vue'
import { getActiveOAuth } from './module'
import { storeRef } from './refs'

/** One ref for the whole view, plus a top-level writable ref per field for `v-model`, as a template unwraps only top-level refs. */
export type OAuthForm = Omit<OAuthFormController, 'store' | 'state' | 'view' | 'setUsername' | 'setPassword'> & {
  view: ComputedRef<OAuthFormView>
  username: WritableComputedRef<string>
  password: WritableComputedRef<string>
}

/** The resource-owner password form; call it inside an effect scope. OAuth 2.1 removed the grant, so `@oidcraft/provider` refuses it. */
export const useOAuthForm = (options: OAuthFormOptions = {}): OAuthForm => {
  const oauth = getActiveOAuth()
  const {
    store,
    state,
    view: _view,
    setUsername,
    setPassword,
    ...actions
  } = createOAuthForm(
    {
      login: parameters => oauth.login(parameters),
      isAuthorized: () => oauth.isAuthorized.value,
      errorDescription: () => oauth.errorDescription.value
    },
    options
  )

  const snapshot = storeRef(store, state)
  // read here, not through the controller, so this computed tracks it
  const view = computed(() => oauthFormView(snapshot.value, oauth.errorDescription.value, actions.maxLength))

  return {
    ...actions,
    view,
    username: computed({ get: () => view.value.username.value, set: setUsername }),
    password: computed({ get: () => view.value.password.value, set: setPassword })
  }
}
