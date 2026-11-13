# @oidcraft/react

A fully OAuth 2.1 compliant React library. It continues `react-oauth-oidc`, whose last version was 1.

```sh
bun add @oidcraft/react
```

Create the instance in your bootstrap, not in a component — interceptors and route loaders need it
before anything renders — and hand it to the provider:

```tsx
import { createOAuth, OAuthProvider } from '@oidcraft/react'

const oauth = createOAuth({
  config: { issuerPath: 'https://accounts.google.com', clientId: '…', scope: 'openid email', pkce: true },
  resourceOrigins: ['https://api.example.com'] // the access token goes to this page's origin, the provider's, and these only
})

createRoot(root).render(
  <OAuthProvider oauth={oauth}>
    <App />
  </OAuthProvider>
)
```

```tsx
import { useOAuth, useOAuthUser } from '@oidcraft/react'

const Account = () => {
  const { isAuthorized, login, logout } = useOAuth()
  const user = useOAuthUser()
  return isAuthorized ? <button onClick={() => logout()}>Sign out {user?.name}</button> : <button onClick={() => login()}>Sign in</button>
}
```

A hook outside an `<OAuthProvider>` throws rather than falling back to some ambient instance: a
missing provider is a wiring mistake, and guessing cannot be done correctly under concurrent SSR.

## Entries

|                             |                                                                                                   |
| --------------------------- | ------------------------------------------------------------------------------------------------- |
| `@oidcraft/react`           | the hooks and `OAuthProvider`, with a `'use client'` banner. `react` is the only required peer.   |
| `@oidcraft/react/core`      | the protocol and client runtime, with no React in its graph and no banner — server components.    |
| `@oidcraft/react/axios`     | the optional axios interceptors. The only entry importing axios, which is what keeps it optional. |
| `@oidcraft/react/component` | the optional MUI login component. Keeps `@mui` out of an app that only wants hooks.               |

`verify-entries.ts` asserts all four claims after every build, because each one fails silently
otherwise: a leaked peer only surfaces for a consumer who never installed it, a missing `'use client'`
only breaks in an app with server components, and a satellite entry that inlined the core instead of
importing it by name would hold a second store that never sees the provider's token.

## Hooks

|                        |                                                                                             |
| ---------------------- | ------------------------------------------------------------------------------------------- |
| `useOAuth()`           | the token's state — `isAuthorized`, `status`, `error` — plus `login`, `logout` and the rest |
| `useAuth()`            | the short form: `isLoggedIn`, `token`, `user`, `error`, `login`, `logout`                   |
| `useOAuthUser()`       | the profile, from the id_token or `userinfo`                                                |
| `useIsAuthorized()`    | one boolean, re-rendering only when it changes                                              |
| `useOAuthSelector(fn)` | any slice of the token, re-rendering only when that slice changes                           |
| `useOAuthFetch()`      | a `fetch` that sends the access token to `resourceOrigins`, and drops it on their 401       |
| `useOAuthForm()`       | the resource-owner password form — see below                                                |

Each reads through `useSyncExternalStore`, with a server snapshot that is empty on purpose: the user
is derived from the id_token, and fetching it is async, so neither resolves during a server render.
The first client render therefore matches the server's markup, and fills in afterwards.

## Where the code lives

Everything above the framework — storage, the token lifecycle, refresh, the authorized fetch, the
derived profile — is `@oidcraft/client`, and the protocol under it is `@oidcraft/core`. Both are
shared with `@oidcraft/vue` and `@oidcraft/angular`, and the protocol half is shared with
`@oidcraft/provider`'s brokering leg as well. Both are ordinary dependencies, so installing this
package pulls those two and `jose`, with `react` as the one required peer.

What is React's here is `hooks.ts` and `provider.tsx`: the store read through
`useSyncExternalStore`, and the context that carries the instance. That is the whole binding.

## `useOAuthForm`

The resource-owner password form, sharing its rules with the Vue and Angular bindings.

```tsx
import { useOAuthForm } from '@oidcraft/react'

const Login = () => {
  const { view, setUsername, setPassword, submit } = useOAuthForm()
  return (
    <form onSubmit={submit}>
      <input value={view.username.value} onChange={event => setUsername(event.target.value)} />
      {view.username.showError && <small>{view.username.error}</small>}
      <input type="password" value={view.password.value} onChange={event => setPassword(event.target.value)} />
      <button type="submit" disabled={!view.valid}>
        Sign in
      </button>
    </form>
  )
}
```

`view` is the whole derived form in one object. `view.username.error` is a code — `'required'`,
`'tooLong'` — not a sentence; the wording is yours. `@oidcraft/react/component` is one way to render
it, and the grant it drives is one OAuth 2.1 removed, so an `@oidcraft/provider` provider will not
accept it.

## SSR

Create one instance per request, never one per module: an instance holds a token, and a module-level
one would hand one request's token to another's render. Call `oauth.dispose()` in a `finally` once
the render is done, so a render that throws still releases that request's subscriptions.

## License

MIT
