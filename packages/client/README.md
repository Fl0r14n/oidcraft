# @oidcraft/client — not published

**Nothing on npm resolves this name.** It is compiled into whichever package uses it
(ARCHITECTURE.md §2.1).

The stateful half of an OpenID Connect client, on top of `@oidcraft/core`: storage, the token
lifecycle, refresh, the authorized `fetch` that retries a 401 into token state, and the profile
derived from the id_token or `userinfo`. It is what `vue-oidc`, `react-oauth-oidc` and `ngx-oauth`
each used to hold their own copy of.

Its consumers are those three and nothing else. `oidcraft` — the provider — uses `@oidcraft/core`
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
