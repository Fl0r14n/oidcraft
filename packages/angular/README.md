# @oidcraft/angular

A fully OAuth 2.1 compliant Angular library. It continues `ngx-oauth`, whose last version was 8.

```ts
import { provideOAuthConfig } from '@oidcraft/angular'

bootstrapApplication(App, {
  providers: [
    provideOAuthConfig({
      config: { issuerPath: 'https://accounts.google.com', clientId: '…', scope: 'openid email', pkce: true },
      resourceOrigins: ['https://api.example.com'] // the access token goes to this page's origin, the provider's, and these only
    })
  ]
})
```

```ts
const { isAuthorized, login, logout } = inject(OAUTH)
```

## Entries

|                          |                                                                                                         |
| ------------------------ | ------------------------------------------------------------------------------------------------------- |
| `@oidcraft/angular`      | the `OAUTH` instance and its providers. `@angular/core` is the only peer.                               |
| `@oidcraft/angular/core` | the protocol and runtime alone, with no Angular in its graph — usable from a route handler or a worker. |

`verify-entries.ts` asserts both claims after every build, plus that **no decorator reaches the
output** — that is the property which lets this package build with tsdown like every other package
here, instead of needing `ng-packagr`.

## Coming from `ngx-oauth` 8

- **No module-level state.** An instance belongs to the injector that created it, not to module
  signals every injector shared, which is what makes one per request safe under concurrent SSR.
- **`OAUTH_USER` is a `Signal<UserInfo | undefined>`**, not a `resource`, derived from the id_token or
  `userinfo`, whichever the session has.
- **Protocol functions are configuration, not injection tokens.** Override them with
  `provideOAuthConfig({ functions: { … } })` rather than by providing `OAUTH_REFRESH` and friends.
- **There is no login component; `oauthForm()` replaces it.** A published Angular component needs
  `ngc`, which needs a TypeScript this workspace does not use (ARCHITECTURE.md §8.4). `oauthForm()` is
  the validation and submit lifecycle as one `view` signal plus the actions, with the markup left to
  you. It drives the **resource-owner password grant**, which OAuth 2.1 removed: an `oidcraft`
  provider does not advertise it, and this is for the IdPs that still accept it.
- **The flow is the shared implementation**, so `state` is validated on the callback, `iss` is checked
  (RFC 9207), the PKCE verifier and nonce travel in a handoff rather than in the token, and a
  repeated callback does not re-exchange a consumed code.

## Where the code lives

Everything above the framework is `@oidcraft/client`, on `@oidcraft/core`, shared with `@oidcraft/vue` and
`@oidcraft/react`. Both are ordinary dependencies, so installing this pulls those two, with
`@angular/core` and `jose` as peers.

What is Angular's here is `signals.ts`: two functions turning the runtime's `Subscribable` into a
signal. That is the whole binding.

## License

MIT
