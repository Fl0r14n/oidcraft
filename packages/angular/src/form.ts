import { computed, inject, type Signal } from '@angular/core'
import { createOAuthForm, type OAuthFormController, type OAuthFormOptions } from '@oidcraft/client'
import { type OAuthFormView, oauthFormView } from '@oidcraft/core'
import { OAUTH } from './oauth'
import { storeSignal } from './signals'

/**
 * One signal for the whole view rather than one per field. A login form has two inputs, so
 * fine-grained reactivity buys nothing here and costs the interface being restated property by
 * property in every binding — which is how the same form ended up written three times before.
 */
export type OAuthForm = Omit<OAuthFormController, 'store' | 'state' | 'view'> & {
  view: Signal<OAuthFormView>
}

/**
 * The resource-owner password form as signals. The rules and the submit lifecycle are
 * `@oidcraft/core`'s and `@oidcraft/client`'s, shared with the Vue and React bindings; this is the
 * reactive wrapper and nothing else.
 *
 * Call it in an injection context. v8 shipped this as a Material component under
 * `ngx-oauth/component`; see the README for why that entry is gone.
 */
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
  // the flow error is read here rather than through the controller so this computed tracks it
  return { ...actions, view: computed(() => oauthFormView(snapshot(), oauth.errorDescription(), actions.maxLength)) }
}
