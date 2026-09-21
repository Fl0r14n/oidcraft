import { createOAuthForm, type OAuthFormController, type OAuthFormOptions } from '@oidcraft/client'
import { type OAuthFormView, oauthFormView } from '@oidcraft/core'
import { type ComputedRef, computed, type WritableComputedRef } from 'vue'
import { getActiveOAuth } from './module'
import { storeRef } from './refs'

/**
 * One ref for the whole view, plus a writable ref per field because `v-model` needs somewhere to
 * write. Those two are separate from `view` deliberately: Vue unwraps a ref in a template only when
 * it is a top-level binding, so `view.username.value` would render the ref rather than the string.
 */
export type OAuthForm = Omit<OAuthFormController, 'store' | 'state' | 'view' | 'setUsername' | 'setPassword'> & {
  view: ComputedRef<OAuthFormView>
  username: WritableComputedRef<string>
  password: WritableComputedRef<string>
}

/**
 * The resource-owner password form. The rules and the submit lifecycle are `@oidcraft/core`'s and
 * `@oidcraft/client`'s, shared with the React and Angular bindings; this is the Vue wrapper.
 *
 * Call it inside a component setup or another effect scope: it subscribes, and the scope is what
 * unsubscribes. OAuth 2.1 removed the grant it drives, so an `oidcraft` provider will not accept it.
 */
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
  // the flow error is read here rather than through the controller so this computed tracks it
  const view = computed(() => oauthFormView(snapshot.value, oauth.errorDescription.value, actions.maxLength))

  return {
    ...actions,
    view,
    username: computed({ get: () => view.value.username.value, set: setUsername }),
    password: computed({ get: () => view.value.password.value, set: setPassword })
  }
}
