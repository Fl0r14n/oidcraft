# vue-oidc

A fully OAuth 2.1 compliant Vue library. Published as `vue-oidc`; the directory is named for its
framework (PLAN.md).

```sh
bun add vue-oidc
```

```ts
import { createOAuth } from 'vue-oidc'

const oauth = createOAuth({
  config: { issuerPath: 'https://accounts.google.com', clientId: '…', scope: 'openid email', pkce: true }
})
app.use(oauth)
```

```vue
<script setup lang="ts">
import { useOAuth, useOAuthUser } from 'vue-oidc'

const { isAuthorized, login, logout } = useOAuth()
const user = useOAuthUser()
</script>
```

## Entries

| | |
| --- | --- |
| `vue-oidc` | the composables and the plugin. `vue` is the only peer. |
| `vue-oidc/core` | the protocol alone, with no Vue in its graph — usable from a request handler or a worker. |
| `vue-oidc/axios` | the optional axios adapter. The only entry importing axios, which is what keeps it optional. |
| `vue-oidc/component` | the optional Vuetify login component, plus `vue-oidc/component.css`. |

`verify-entries.ts` asserts all four claims after every build, because each one fails silently
otherwise: a leaked peer only surfaces for a consumer who never installed it, and a satellite entry
importing the root relatively would inline a second `oauthKey` and quietly resolve nothing.

## Where the code lives

Everything above the framework — storage, the token lifecycle, refresh, the authorized fetch, the
derived profile — is `@oidcraft/client`, and the protocol under it is `@oidcraft/core`. Both are
shared with `ngx-oauth` and `react-oauth-oidc`, and the protocol half is shared with the `oidcraft`
provider's federation leg as well. Both are compiled in rather than depended on, so installing this
package pulls `vue` and nothing else.

What is Vue's here is `refs.ts`: two functions turning the core's `Subscribable` into a `Ref`. That
is the whole binding.

## `useOAuthForm`

The resource-owner password form as refs, sharing its rules with the React and Angular bindings.

```vue
<script setup lang="ts">
import { useOAuthForm } from 'vue-oidc'

const { username, password, errors, showErrors, valid, submit } = useOAuthForm()
</script>

<template>
  <form @submit.prevent="submit()">
    <input v-model="username" />
    <small v-if="showErrors.username">{{ errors.username }}</small>
    <input v-model="password" type="password" />
    <button type="submit" :disabled="!valid">Sign in</button>
  </form>
</template>
```

The shape is **flat** where the React and Angular bindings nest a field object. Vue unwraps a ref in
a template only when it is a top-level binding, so a nested `form.username.value` renders the ref
rather than the string and `v-model` binds the wrong thing.

`errors.username` is a code — `'required'`, `'tooLong'` — not a sentence; the wording is yours.
`vue-oidc/component` is one way to render it, and the grant it drives is one OAuth 2.1 removed, so an
`oidcraft` provider will not accept it.

## SSR

`createOAuth()` opens a **detached** effect scope, so one instance per request stays isolated and a
render that never disposes leaks that request's subscriptions. Call `disposeOAuth(app)` in a
`finally`, so a render that throws still cleans up.

## License

MIT
