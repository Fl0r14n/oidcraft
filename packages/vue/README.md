# @oidcraft/vue

A fully OAuth 2.1 compliant Vue library. It continues `vue-oidc`, whose last version was 6.

```sh
bun add @oidcraft/vue
```

```ts
import { createOAuth } from '@oidcraft/vue'

const oauth = createOAuth({
  config: { issuerPath: 'https://accounts.google.com', clientId: '…', scope: 'openid email', pkce: true },
  resourceOrigins: ['https://api.example.com'] // the access token goes to this page's origin, the provider's, and these only
})
app.use(oauth)
```

```vue
<script setup lang="ts">
import { useOAuth, useOAuthUser } from '@oidcraft/vue'

const { isAuthorized, login, logout } = useOAuth()
const user = useOAuthUser()
</script>
```

## Entries

|                           |                                                                                              |
| ------------------------- | -------------------------------------------------------------------------------------------- |
| `@oidcraft/vue`           | the composables and the plugin. `vue` is the only peer.                                      |
| `@oidcraft/vue/core`      | the protocol alone, with no Vue in its graph — usable from a request handler or a worker.    |
| `@oidcraft/vue/axios`     | the optional axios adapter. The only entry importing axios, which is what keeps it optional. |
| `@oidcraft/vue/component` | the optional Vuetify login component, plus `@oidcraft/vue/component.css`.                    |

`verify-entries.ts` asserts all four claims after every build, because each one fails silently
otherwise: a leaked peer only surfaces for a consumer who never installed it, and a satellite entry
importing the root relatively would inline a second `oauthKey` and quietly resolve nothing.

## Where the code lives

Everything above the framework — storage, the token lifecycle, refresh, the authorized fetch, the
derived profile — is `@oidcraft/client`, and the protocol under it is `@oidcraft/core`. Both are
shared with `@oidcraft/angular` and `@oidcraft/react`, and the protocol half is shared with
`@oidcraft/provider`'s brokering leg as well. Both are ordinary dependencies, so installing this
package pulls those two and `jose`, with `vue` as the one required peer.

What is Vue's here is `refs.ts`: two functions turning the core's `Subscribable` into a `Ref`. That
is the whole binding.

## `useOAuthForm`

The resource-owner password form as refs, sharing its rules with the React and Angular bindings.

```vue
<script setup lang="ts">
import { useOAuthForm } from '@oidcraft/vue'

const { view, username, password, submit } = useOAuthForm()
</script>

<template>
  <form @submit.prevent="submit()">
    <input v-model="username" />
    <small v-if="view.username.showError">{{ view.username.error }}</small>
    <input v-model="password" type="password" />
    <button type="submit" :disabled="!view.valid">Sign in</button>
  </form>
</template>
```

`view` is the whole derived form in one ref; `username` and `password` are writable because
`v-model` needs somewhere to write. They are separate deliberately — Vue unwraps a ref in a template
only at the top level, so `view.username.value` would render the ref rather than the string.

`view.username.error` is a code — `'required'`, `'tooLong'` — not a sentence; the wording is yours.
`@oidcraft/vue/component` is one way to render it, and the grant it drives is one OAuth 2.1 removed, so an
`@oidcraft/provider` provider will not accept it.

## SSR

`createOAuth()` opens a **detached** effect scope, so one instance per request stays isolated and a
render that never disposes leaks that request's subscriptions. Call `disposeOAuth(app)` in a
`finally`, so a render that throws still cleans up.

## License

MIT
