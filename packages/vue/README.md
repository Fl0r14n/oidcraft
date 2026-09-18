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
derived profile — is `@oidcraft/core/client`, shared with `ngx-oauth`, `react-oauth-oidc` and the
`oidcraft` provider's federation leg. It is compiled in rather than depended on, so installing this
package pulls `vue` and nothing else.

What is Vue's here is `refs.ts`: two functions turning the core's `Subscribable` into a `Ref`. That
is the whole binding.

## SSR

`createOAuth()` opens a **detached** effect scope, so one instance per request stays isolated and a
render that never disposes leaks that request's subscriptions. Call `disposeOAuth(app)` in a
`finally`, so a render that throws still cleans up.

## License

MIT
