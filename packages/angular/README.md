# ngx-oauth

A fully OAuth 2.1 compliant Angular library. Published as `ngx-oauth`; the directory is named for its
framework (PLAN.md).

```ts
import { provideOAuthConfig } from 'ngx-oauth'

bootstrapApplication(App, {
  providers: [
    provideOAuthConfig({
      config: { issuerPath: 'https://accounts.google.com', clientId: '…', scope: 'openid email', pkce: true }
    })
  ]
})
```

```ts
const { isAuthorized, login, logout } = inject(OAUTH)
```

## Entries

| | |
| --- | --- |
| `ngx-oauth` | the `OAUTH` instance and its providers. `@angular/core` is the only peer. |
| `ngx-oauth/core` | the protocol and runtime alone, with no Angular in its graph — usable from a route handler or a worker. |

`verify-entries.ts` asserts both claims after every build, plus that **no decorator reaches the
output** — that is the property which lets this package build with tsdown like every other package
here, instead of needing `ng-packagr`.

## Changed from v8

- **No module-level state.** v8 kept `oauthConfig`, `config` and the JWKS in module signals, so every
  injector shared one instance. An instance now belongs to the injector that created it, which is what
  makes one per request safe under concurrent SSR — a process-wide holder cannot be answered correctly
  there, and hands one request another request's token.
- **`OAUTH_USER` is a `Signal<UserInfo | undefined>`**, not a `resource`. The profile is derived by the
  shared runtime, from the id_token or `userinfo`, whichever the session actually has.
- **Protocol functions are configuration, not injection tokens.** Override them with
  `provideOAuthConfig({ functions: { … } })` rather than by providing `OAUTH_REFRESH` and friends.
- **`ngx-oauth/component` is gone, replaced by `oauthForm()`.** A published Angular *component* has to
  be compiled by `ngc` into partial form, and `ngc` requires a TypeScript this workspace does not use
  (ARCHITECTURE.md §8.4). What the Material form was actually worth — the validation, the submit
  lifecycle, the rule that a pristine field does not show an error, the decision to keep the username
  and clear the password on a rejection — is `oauthForm()`, as signals, with the markup left to you.
  `react-oauth-oidc` ships the same thing as `useOAuthForm`.

  Note that it drives the **resource-owner password grant**, which OAuth 2.1 removed: an `oidcraft`
  provider does not advertise it, and this is for the IdPs that still accept it.
- **The flow is the shared implementation**, so `state` is validated on the callback, `iss` is checked
  (RFC 9207), the PKCE verifier and nonce travel in a handoff rather than in the token, and a
  repeated callback does not re-exchange a consumed code.

## Where the code lives

Everything above the framework is `@oidcraft/client`, on `@oidcraft/core`, shared with `vue-oidc` and
`react-oauth-oidc`. Both are compiled in rather than depended on, so installing this pulls
`@angular/core` and `jose` and nothing else.

What is Angular's here is `signals.ts`: two functions turning the runtime's `Subscribable` into a
signal. That is the whole binding.

## License

MIT
