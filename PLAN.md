# Plan

What is left, in order. `REQUIREMENTS.md` says what it must do, `ARCHITECTURE.md` how.
This file is working state: tick items off and add notes as work lands. Git history holds what
was done.

## Status

**Implemented, as of 2026-11-13**, with 1341 passing tests (215 more skip without Postgres and
Redis) and `bun run verify` as the gate: every functional requirement in `REQUIREMENTS.md`, FR-T6,
FR-C21 and FR-A4's Postgres included. `metadata.test.ts` exercises every advertised discovery value
rather than reading it. Published as `@oidcraft/*` — `core` 0.4.0, `client` 0.3.0, the provider
0.4.0, `adapter` and the four storage adapters 0.2.0, `vue` 9.0.0, `react` 4.0.0, `angular` 11.0.0 —
with the docs site at https://fl0r14n.github.io/oidcraft/. `adapter` 0.2.0 still names `core` ^0.3.0,
for types and `sha256` identical in 0.4.0, so a consumer holds both copies until `adapter` next moves.

**Provider 0.3.0 and earlier are not to be put in front of real identities**: they ship a session
takeover through `sid` and the other security faults the review after that release found, fixed in
0.4.0. The review's correctness and small findings, and the provider follow-ups, are fixed on `main`,
unreleased.

The authorization code grant with mandatory PKCE, interaction suspend/resume, token issuance with
rotation and replay revocation, UserInfo, revocation, introspection, logout in both directions,
DPoP with nonces, PAR, JAR by value, the `claims` parameter, dynamic client registration with RFC 7592 management, the
device grant, CIBA in poll and ping, token exchange, RAR, step-up, pairwise subjects, identity
brokering with home-realm discovery chosen by the provider, five storage adapters (memory, Drizzle,
Kysely, TypeORM, Redis) passing one conformance suite, four runtime context providers, a management
API and an admin UI.

### What is NOT done, and will not be silently forgotten

**The OpenID Foundation suite's `basic`, `config` and FAPI 2.0 plans gate CI** (NFR-C1), with the
refusals `conformance/README.md` lists. That is a passing run, not certification: three `basic`
modules and five FAPI ones end in REVIEW, which a person signs off with screenshots only when
certifying. Each was pre-checked from its page source on 2026-11-13 and shows the page its module
asks for.

**No deployment has run this in production**, against a real relying party that was not also written
here, or under any load. Implemented is not certified: no `FR-*` has been checked by anything but
its author and its tests.

**The `acr` a login reports is the host's word.** The host is the authenticator: an essential `acr`
in the `claims` parameter (FR-C22) refuses a login that reports less, but nothing checks the report.

### Decided against, rather than pending

- **JAR by reference** (`request_uri` pointing at the client's own server) — resolving it means the
  core fetching a URL the client chose, which is outbound I/O it does not do (FR-A1). A host that
  needs it resolves and pushes the result. See `REQUIREMENTS.md` FR-C12.
- **Kysely on MySQL** — removed from FR-A4. MySQL has no `on conflict … do update` and no
  `returning`, which the Kysely adapter uses for every upsert and insert-if-absent, so it needs its
  own code paths, and promising a database nothing tests is a claim rather than a feature.
- **Editing upstream providers from the admin UI** — an issuer and client credentials are deployment
  configuration, not runtime state. The admin shows what is configured.
- **CIBA push mode**, **OpenID Federation 1.0** trust chains (`G-1`, unless a deployment needs it),
  and **upstream SAML** in-tree (`G-4`).
- **A stateless DPoP nonce** — a nonce demand is a storage write a public client can trigger, but
  every proof already costs one for its `jti`, nonce rows live five minutes and are pruned, and a
  stateless nonce would put a new secret in the configuration of a feature off by default.
- **Merging scopes in the SQL adapters' grant upsert** — merging JSON text is not portable across
  SQLite and Postgres, so they replace on the `(account_id, client_id)` conflict. `recordConsent`
  reads back and writes again; a first consent landing after the other's read-back still loses its
  scopes, and the person is asked once more (FR-I4).
- **A single-statement bounded prune** — a composite key has no portable one across SQLite and
  Postgres, so the session and replay sweeps delete a row at a time (NFR-P3).
- **Renaming the demo's `/federation/callback`** — it is the redirect URI registered with Google
  (`.env.example`), and renaming a URL people have registered breaks their sign-in for a word.

## Next, in this order

1. **Release the review's fixes** — below, all done 2026-11-13 on `main`. The release needs
   `adapter` 0.2.1 (the `revoked_family` kind, the suite's new checks, the identity key),
   `drizzle` and `kysely` 0.2.1, `typeorm` 0.3.0 (`OIDCRAFT_ENTITIES` split by dialect), `core`
   0.5.0 (the `token` check), `client` 0.4.0 (the handoff in `sessionStorage`), the provider 0.5.0
   and the bindings. The provider follow-ups below ride in the provider's 0.5.0: `onAudit` now hears
   replays and failed client authentications, and a body that is not form-encoded is a 415.
   So does the `claims` parameter (FR-C22): `InteractionRequest.claims` is new, and a consent answer
   to a request naming claims must repeat them in `consent.claims` — a host's own consent screen
   needs that one line, as `apps/demo-server`'s did. `@oidcraft/ui`'s consent screen lists them.
   `adapter`'s `AccountStore.claims` documents its third argument, which the stores now honour.

## Review — 2026-11-13, after the release

Four readers in parallel, none told what the code was meant to do: the provider core; the broker and
local accounts; storage, TypeORM and `@oidcraft/ui`; the client libraries. Each finding was traced in
the code before it was written here. Its security findings are fixed on `main` and wait on the
release above. In fix order.

**Correctness**

- [x] `upstreamLogout` throwing loses the back-channel notifications of a session already destroyed;
      a malformed stored `frontchannelLogoutUri` blocks logout with a 500; `id_token_hint`'s `typ` is
      not checked
- [x] Revocation racing a refresh: the FAPI rewrite can resurrect a revoked token, a rotated one can
      land in a family just revoked; `fromKv.consume` is read-then-insert
- [x] `authorization_details=[null]` is a 500; device and CIBA requests do not check the client's
      `grant_types`; a JAR-by-value request resumed after an interaction travels as plain parameters
- [x] Accounts: a password reset leaves `sign_in_attempts` locks in place
- [x] Client: redirect classification matches `?barcode=`; `unreachable` is inferred from an echo;
      the handoff shares the token slot, so a login in one tab ends the others; a URL passed to
      `oauthCallback` is not cleaned; a non-redirecting logout and the refresh lock have no timeout; a
      storage key changed mid-refresh; an expired ID token becomes a truthy profile; `logoutPath` skips
      `assertSecure`; React's error hook reads `errorDescription` only
- [x] Storage: TypeORM's entities say `bigint` where the SQLite migrations say `integer`, so its schema
      builder rebuilds every table; the SQL adapters ignore `Grant.expiresAt`; artifact prune can delete a
      row rewritten since its select; the conformance suite never prunes artifacts and cannot tell a
      merging grant upsert from a replacing one

**Small**

- [x] The broker's binding cookie can be planted from a sibling subdomain; NAT64 addresses share a
      /64; `@oidcraft/ui` asset paths are fixed at `/assets`; TypeORM deletes trust the host's
      undefined-where setting; `fromKv` identity keys are not encoded. The binding cookie is `__Host-`
      over https; TypeORM refuses a missing value in a lookup as well as a delete, since the same
      setting makes a find match any row; `fromKv`'s identity key changed, so a Redis store's links
      made before it are not found

## Provider follow-ups

From a read of `provider.ts`, `config.ts` and `authorize/authorization.ts`, the rest only grepped: a
list of what was seen, not a review. Each fix starts with the requirement's text and a test that
shows it. In order.

**Before 1.0**

- [x] Security events reach no hook. FR-M3 widened rather than a second hook: `onAudit` hears
      `token.replay` (with the grant and family it revoked) and `client.authentication_failed`, carried
      on the refusal's `OAuthError` and emitted where the request ends. A lockout and a wrong device code
      were never invisible: the host calls `accounts` and `provider.device.*` and is answered. A failing
      audit hook goes to `onError` and changes no answer. FR-M3
- [x] A throwing `onLogout` turns a logout that happened into a 500. Both logout hooks are guarded as
      `onError` is (`hooks.ts`), each failure reported there. FR-C11, NFR-D5
- [x] Nine endpoints read the body with no content-type check. `readForm` refuses a non-empty body
      that is not form-encoded with a 415; the size cap stays the host's, as NFR-S12 already puts the
      rate limits, and _Before production_ and the security guide say so. NFR-S12
- [x] `ResolvedConfig` is `ProviderConfig` written out three times. Now `ProviderConfig` with its
      defaulted fields resolved; every hook is carried through by the spread, which a test pins. NFR-D2

**Smaller**

- [x] `suspend` took an optional `client`; it is required, so a consent suspension carries it too. FR-F4
- [x] `grant as Grant` — a missing grant now asks for consent in its own right
- [x] `config.ts` tells the host to implement `upsert`
- [x] Two doc comments stacked on `Provider.handle` — already gone by the time this was picked up
- [x] The route table is a line per route: the endpoints already take `(config, request, certificate, caller)`
- [x] `gaps.test.ts` and `flow.test.ts` are split beside the modules they test, over one harness,
      `test-flow.ts`, whose adapter gets its own `accounts` per test — the old shared one let a test's
      override of `claims` leak into the next file. `small.test.ts` is named the same way and was left

## Still open on the client libraries

- **The login component's props type is written out, not derived from the protocol.** The SFC imports
  it from `component/props.ts`, which `@vue/compiler-sfc` reads through the `fs` that
  `packages/vue/tsdown.config.ts` hands it, because TypeScript 7 has no `ts.sys` for it to use. Bun was
  never the cause. Without TypeScript's resolver it follows a relative import but not a package one,
  so `props.ts` cannot be `Partial<ResourceOwnerParameters & …>` from `@oidcraft/core`; two
  assignments there fail the typecheck on drift instead.
- **The declaration build sees the SFC through an ambient `*.vue` shim and a cast**
  (`component/index.ts`). `rolldown-plugin-dts` builds Vue declarations through Volar, which only its
  `tsc` generator accepts, and that needs TypeScript's JavaScript API, which TypeScript 7 does not
  ship. Checked 2026-11-13 against 0.30.2: its `oxc` generator refuses Volar too.
- If `@vue/compiler-sfc` ever stops resolving what it does now, `@oidcraft/vue/component` meets the
  question `@oidcraft/angular`'s component did (below): that entry already needed both workarounds
  above to ship at all.

## Waiting on upstream

**TypeScript 7.1, in beta (`7.1.0-beta`).** `rolldown-plugin-dts` 0.30.x warns that its `tsgo`
generator on TypeScript 7.0 "will be removed in the next minor", which would fail every package's
declaration build here, not only Vue's. The lockfile holds 0.30.1 and CI installs frozen, but the root
`package.json` asks for `tsdown@latest`, so the next lockfile refresh can bring it in. Move to 7.1 when
it is stable, before taking `rolldown-plugin-dts` 0.31; 7.1 is also what the plugin names for custom
languages, so the shim above is worth retrying then.

**Bun, checked 2026-11-13.** Nothing tracks exposing the client certificate to a `Bun.serve` handler:
no issue, no PR. The only movement is on `node:https`: oven-sh/bun#16834 (its `req.socket` is not a
`TLSSocket`) has a fix open, oven-sh/bun#37255, which adds `getPeerCertificate()` to it — still open
and unmerged, last touched 2026-11-06. If it lands, mTLS works on Bun through `./runtimes/node`'s
`toNodeHandler` on a `node:https` server, not through `Bun.serve`, and G-8's re-verification is the
first thing to repeat.

## Decisions waiting on an answer

None.

## Recorded here because code and docs point at it

**Why `@oidcraft/angular` ships no component, and so no decorator.** v8 (`ngx-oauth`) published a
secondary entry, `ngx-oauth/component`: a standalone Material login form, a real `@Component` with an
inline template, built by `ng-packagr`. That cannot ship from tsdown. `erasableSyntaxOnly` forbids the
decorator, and relaxing it would not be enough: an Angular component published without `ngc` reaches
consumers as JIT, which breaks under a production build, and partial compilation is what `ng-packagr`
exists to do. So v9 ships no component. `oauthForm()` in the root entry carries what the Material
form was worth — validation, the submit lifecycle, when an error may show, keeping the username and
clearing the password on a rejection — as signals, with the markup left to the host, as `useOAuthForm`
does in Vue and React. That keeps `packages/angular` on tsdown and TypeScript 7, inside the workspace
and inside `verify`, and `verify-entries.ts` asserts no decorator reaches its output. Rejected: a
nested `ng-packagr` install building only `./component`, and moving the package out of the workspace;
both put a published entry outside the gate that checks everything else. `oauthForm()` drives the
resource-owner password grant, which OAuth 2.1 removed, so `apps/demo-server` does not advertise it
and `apps/demo-angular` cannot demonstrate it; it is there for the IdPs that still accept it, as v8's
component was.

**The old npm names.** The unscoped `oidcraft@0.0.1` is a name reservation, not the provider, and is
deprecated in favour of `@oidcraft/provider`. `vue-oidc`, `react-oauth-oidc` and `ngx-oauth` are
deprecated in favour of `@oidcraft/vue`, `@oidcraft/react` and `@oidcraft/angular`, their published
versions still working, and their repositories archived.
