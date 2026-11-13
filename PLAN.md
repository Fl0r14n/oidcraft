# Plan

What is left, in order. `REQUIREMENTS.md` says what it must do, `ARCHITECTURE.md` how.
This file is working state: tick items off and add notes as work lands. Git history holds what
was done.

## Status

**Implemented, as of 2026-11-13**, with 1266 passing tests (190 more skip without Postgres and
Redis) and `bun run verify` as the gate: every functional requirement in `REQUIREMENTS.md`, FR-T6,
FR-C21 and FR-A4's Postgres included. `metadata.test.ts` exercises every advertised discovery value
rather than reading it. Published as `@oidcraft/*` — `core` 0.4.0, `client` 0.3.0, the provider
0.4.0, `adapter` and the four storage adapters 0.2.0, `vue` 9.0.0, `react` 4.0.0, `angular` 11.0.0 —
with the docs site at https://fl0r14n.github.io/oidcraft/. `adapter` 0.2.0 still names `core` ^0.3.0,
for types and `sha256` identical in 0.4.0, so a consumer holds both copies until `adapter` next moves.

**Provider 0.3.0 and earlier are not to be put in front of real identities**: they ship a session
takeover through `sid` and the other security faults the review after that release found, fixed in
0.4.0. The review's correctness and small findings, and the provider follow-ups, are open.

The authorization code grant with mandatory PKCE, interaction suspend/resume, token issuance with
rotation and replay revocation, UserInfo, revocation, introspection, logout in both directions,
DPoP with nonces, PAR, JAR by value, dynamic client registration with RFC 7592 management, the
device grant, CIBA in poll and ping, token exchange, RAR, step-up, pairwise subjects, identity
brokering with home-realm discovery chosen by the provider, five storage adapters (memory, Drizzle,
Kysely, TypeORM, Redis) passing one conformance suite, four runtime context providers, a management
API and an admin UI.

### What is NOT done, and will not be silently forgotten

**The OpenID Foundation suite's `basic`, `config` and FAPI 2.0 plans gate CI** (NFR-C1), with the
refusals `conformance/README.md` lists. That is a passing run, not certification: three `basic`
modules and five FAPI ones end in REVIEW, which a person signs off with screenshots only when
certifying.

**No deployment has run this in production**, against a real relying party that was not also written
here, or under any load. Implemented is not certified: no `FR-*` has been checked by anything but
its author and its tests.

**The `claims` request parameter is not implemented**, so the `acr` a login reports stays the host's
word: the host is the authenticator, and an essential `acr` would be enforceable only through
`claims`.

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

1. **The correctness and small findings of the review after the release** — below.
2. **Provider follow-ups**, below. Before 1.0.

## Review — 2026-11-13, after the release

Four readers in parallel, none told what the code was meant to do: the provider core; the broker and
local accounts; storage, TypeORM and `@oidcraft/ui`; the client libraries. Each finding was traced in
the code before it was written here. Its security findings are fixed on `main` and wait on the
release above. In fix order.

**Correctness**

- [x] `upstreamLogout` throwing loses the back-channel notifications of a session already destroyed;
  a malformed stored `frontchannelLogoutUri` blocks logout with a 500; `id_token_hint`'s `typ` is
  not checked
- [ ] Revocation racing a refresh: the FAPI rewrite can resurrect a revoked token, a rotated one can
  land in a family just revoked; `fromKv.consume` is read-then-insert
- [ ] `authorization_details=[null]` is a 500; device and CIBA requests do not check the client's
  `grant_types`; a JAR-by-value request resumed after an interaction travels as plain parameters
- [ ] Accounts: a password reset leaves `sign_in_attempts` locks in place
- [ ] Client: redirect classification matches `?barcode=`; `unreachable` is inferred from an echo;
  the handoff shares the token slot, so a login in one tab ends the others; a URL passed to
  `oauthCallback` is not cleaned; a non-redirecting logout and the refresh lock have no timeout; a
  storage key changed mid-refresh; an expired ID token becomes a truthy profile; `logoutPath` skips
  `assertSecure`; React's error hook reads `errorDescription` only
- [ ] Storage: TypeORM's entities say `bigint` where the SQLite migrations say `integer`, so its schema
  builder rebuilds every table; the SQL adapters ignore `Grant.expiresAt`; artifact prune can delete a
  row rewritten since its select; the conformance suite never prunes artifacts and cannot tell a
  merging grant upsert from a replacing one

**Small**

- [ ] The broker's binding cookie can be planted from a sibling subdomain; NAT64 addresses share a
  /64; `@oidcraft/ui` asset paths are fixed at `/assets`; TypeORM deletes trust the host's
  undefined-where setting; `fromKv` identity keys are not encoded

## Provider follow-ups

From a read of `provider.ts`, `config.ts` and `authorize/authorization.ts`, the rest only grepped: a
list of what was seen, not a review. Each fix starts with the requirement's text and a test that
shows it. In order.

**Before 1.0**

- [ ] Security events reach no hook. `onAudit` fires for management and registration writes only: a
  detected replay revokes its family in silence (`token/family.ts:6`), and a failed client
  authentication, a lockout and a wrong device code are as invisible. Either widen `onAudit` or add
  a hook for these, and decide which in `REQUIREMENTS.md` first. FR-M3
- [ ] A throwing `onLogout` turns a logout that happened into a 500: the session is already ended
  when the hook is awaited, and the notifications are lost (`provider.ts:165`). Guard it as `onError`
  is guarded and report the failure there; `onFrontChannelLogout` the same. FR-C11, NFR-D5
- [ ] Nine endpoints read `new URLSearchParams(await request.text())`, with no content-type check and
  no bound on the body. One `readForm(request)` for all of them; if the size cap stays the host's,
  the README's _Before production_ says so beside the rate limiting. NFR-S12
- [ ] `ResolvedConfig` is `ProviderConfig` written out three times — the type, the resolved type and
  the returned literal, 28 fields each (`config.ts`) — so a new hook is three edits and a missed one
  is `undefined` without an error. Derive it: defaults for what has them, the hooks carried through.
  NFR-D2

**Smaller**

- [ ] `authorize` takes an optional `client`, and without one `suspend` drops that client's
  `upstreamProviders` restriction (`authorize/authorization.ts`). Its one caller passes it; make it
  required. FR-F4
- [ ] `grant as Grant` (`authorize/authorization.ts:336`) holds only because `openid` is always
  requested, so a missing grant always has scopes outstanding. A check in place of the cast
- [ ] `config.ts:358` tests `clients.upsert` and tells the host to implement "create"
- [ ] Two doc comments stacked on `Provider.handle`, the first attached to nothing (`provider.ts`)
- [ ] The route table adapts `(config, request, context, caller)` to each endpoint's own argument
  order (`provider.ts`). Endpoints that take the `Handler` shape make it a line per route
- [ ] `gaps.test.ts` and `flow.test.ts` are named for when they were written. Move each case beside
  the module it tests

## Still open on the client libraries

- **`@vue/compiler-sfc` cannot resolve an imported type under Bun** ("No fs option provided to
  compileScript in non-Node environment"), so the login component's props are written out literally
  in the SFC and pinned to the protocol by two assignments in `component/props.ts`. Not a version
  problem: `unplugin-vue` 8.0.0 is the latest there is, and it fails the same way.
- **The declaration build cannot use the Vue language plugin**, because `rolldown-plugin-dts` refuses
  TypeScript 7 for SFCs. The entry is typed through an ambient `*.vue` shim and a cast instead, which
  is why `component/index.ts` casts through `unknown` — `vue-tsgo` and the dts build genuinely see
  that module differently.
- If `@vue/compiler-sfc` ever stops resolving what it does now, `@oidcraft/vue/component` meets the
  question `@oidcraft/angular`'s component did (below): that entry already needed both workarounds
  above to ship at all.
- The old ngx-oauth sample committed a live Google OAuth client id and secret (`app.config.ts`). It
  was not carried over, but it is still in that repository's history and is worth rotating.

## Waiting on upstream

**Bun, checked 2026-11-11.** Nothing tracks exposing the client certificate to a `Bun.serve` handler:
no issue, no PR. The only movement is on `node:https`: oven-sh/bun#16834 (its `req.socket` is not a
`TLSSocket`) has a fix open, oven-sh/bun#37255, which adds `getPeerCertificate()` to it — open,
unreviewed and in conflict with `main`. If it lands, mTLS works on Bun through `./runtimes/node`'s
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
