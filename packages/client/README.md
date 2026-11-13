# @oidcraft/client

```sh
bun add @oidcraft/client
```

The stateful half of an OpenID Connect client, on top of `@oidcraft/core`: storage, the token
lifecycle, refresh, the authorized `fetch` that retries a 401 into token state, and the profile
derived from the id_token or `userinfo`. It is what `@oidcraft/vue`, `@oidcraft/react` and `@oidcraft/angular`
are built on, and what a framework without a binding here builds on directly.

A sign-in in progress keeps its handoff — `state`, `nonce`, the PKCE verifier — under its own `state`
in `localStorage`, expiring after ten minutes, never in the token every tab shares: starting a
sign-in in one tab signs none of the others out, and the callback may land in any tab. A callback
that fails, or that nobody started, never ends a live session.

Refresh is one at a time across tabs, not only within one: it runs under a Web Lock named after the
storage key, and reads storage again once it holds it, so a tab that waited takes the token another
tab just wrote instead of presenting the refresh token that tab spent. A provider that rotates
refresh tokens treats that as a replay and signs the browser out. Where Web Locks are missing, as
when rendering on a server, each instance is on its own.

The access token goes only to this page's origin, the provider's, and the origins named in
`resourceOrigins` — an API on another host is listed there (`resourceOrigins: ['https://api.example.com']`).
A call to anywhere else, through the authorized `fetch` or the axios interceptors, carries no token,
and its 401 leaves the session alone. A 401 from where the token did go ends the session, and of its
body only `error` and `error_description` become the token state. An HTTP client of your own reports
a 401 through `onUnauthorized(url, body)`, which applies the same rule; the axios interceptors do.

The ID token is verified against the provider's `jwks_uri`, and refused when there is none.
`strictJwt: false` is the explicit way to accept one unchecked, for a provider that publishes no keys.

Its consumers are those three and any other browser client. `@oidcraft/provider` uses `@oidcraft/core`
directly and must never reach this package, which is the entire reason the two are separate rather
than two entries of one.

## The reactive primitive

```ts
type Subscribable<S> = {
  getState: () => S
  subscribe: (listener: (state: S, previous: S) => void) => () => void
}

watchStore(store, selector, callback, { immediate })
```

That is all of it. Every `watch` in every binding is over an **explicit source list** rather than
auto-tracked, so a selector plus an equality check is the entire requirement — there is no dependency
graph here, and therefore no glitch and no diamond to get wrong. A binding adapts `Subscribable` from
outside: Vue with `shallowRef` plus a subscription, React with `useSyncExternalStore`, Angular with a
signal.

Nothing in this package imports a framework, and nothing may.

## The password form

`createOAuthForm(oauth, options)` is the resource-owner password form with no framework and no
markup: two fields, validation, the submit lifecycle, a dismissable flow error. It lives here so the
three bindings share one copy of the rules — when a field may show an error, what survives a
rejected attempt, when a dismissed error comes back.

Only the **stateful** half is here. The rules and the derivation — `oauthFieldError`,
`oauthFieldErrors`, `oauthFormView` — are in `@oidcraft/core`, because they are pure and the
provider's own server-rendered login screen validates against exactly the same ones. The split is by
whether a thing needs a browser, not by who consumes it.

Errors are codes — `'required'`, `'tooLong'` — never sentences. The wording belongs to whoever writes
the markup, and to their locale.

OAuth 2.1 removed the resource-owner password grant, so an `@oidcraft/provider` provider does not advertise it.
This is for the providers that still accept it.

## Notes worth keeping

- **A write is persisted before listeners run.** A listener commonly navigates — `authorize`,
  `logout` — and persisting at write time makes that safe by construction rather than by unload
  timing.
- **Construction is inert.** An instance is normally built at module scope, where a side effect runs
  on import: before a test can install its mocks, and during an SSR pass that may only need the type.
  `start()` arms it; `dispose()` disarms it and is what makes one instance per request safe.
- **The callback dedupe is permanent per instance, not per request.** A browser Back into the
  callback url would otherwise re-exchange a code the IdP has already consumed, and the
  `invalid_grant` that comes back ends a session that was working.
- **A stale `userinfo` response cannot land on the next session.** Every sync takes a ticket and drops
  its result if another started meanwhile.
