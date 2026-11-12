# Plan

What is left, in order. `REQUIREMENTS.md` says what it must do, `ARCHITECTURE.md` how.
This file is working state: tick items off and add notes as work lands.

## Status

**Implemented, as of 2026-11-11**, with 1107 passing tests (151 more skip without Postgres and Redis) and `bun run verify` as the gate — everything
below, FR-T6, FR-C21 and FR-A4's Postgres included. Published as `@oidcraft/*` (the move below), with
the docs site at https://fl0r14n.github.io/oidcraft/. Items 1–11 under _Next_ are done; item 12, the
2026-11-12 review, is open, and until its security findings are fixed this is not a provider to put
real identities behind.

The authorization code grant with mandatory PKCE, interaction suspend/resume, token issuance with
rotation and replay revocation, UserInfo, revocation, introspection, logout in both directions,
DPoP with nonces, PAR, JAR by value, dynamic client registration with RFC 7592 management, the
device grant, CIBA in poll and ping, token exchange, RAR, step-up, pairwise subjects, identity
brokering with home-realm discovery chosen by the provider, five storage adapters (memory, Drizzle, Kysely, TypeORM, Redis) passing one
conformance suite, four runtime context providers, a management API and an admin UI.

### What is NOT done, and will not be silently forgotten

**The OpenID Foundation suite's `basic`, `config` and FAPI 2.0 plans gate CI** (NFR-C1), with the
refusals `conformance/README.md` lists. That is a passing run, not certification: three `basic`
modules and five FAPI ones end in REVIEW, which a person signs off with screenshots only when
certifying.

**No deployment has run this in production**, against a real relying party that was not also written
here, or under any load.

### Decided against, rather than pending

- **JAR by reference** (`request_uri` pointing at the client's own server) — resolving it means the
  core fetching a URL the client chose, which is outbound I/O it does not do (FR-A1). A host that
  needs it resolves and pushes the result. See `REQUIREMENTS.md` FR-C12.
- **Kysely on MySQL** — removed from FR-A4. MySQL has no `on conflict … do update` and no
  `returning`, which the Kysely adapter uses for every upsert and insert-if-absent, so it needs its
  own code paths, and promising a database nothing tests is a claim rather than a feature.
- **Editing upstream providers from the admin UI** — an issuer and client credentials are deployment
  configuration, not runtime state. The admin shows what is configured.
- **CIBA push mode**, **OpenID Federation 1.0** trust chains (`G-1`, unless a deployment needs it), and
  **upstream SAML** in-tree (`G-4`).

## M0 — foundation

- [x] CI: `biome ci`, build + `verify-entries`, typecheck, `bun test` on push and PR
- [x] `exports.test.ts`: the exports map, the source tree and the build entries agree

- [x] Root entry: config construction with validation (NFR-D2), route table, error responses
- [x] `KeyStore` + JWKS endpoint + discovery document (FR-C6, FR-C10)
- [x] `oidcraft/adapters/memory` and the shared adapter-conformance suite (FR-A3, FR-A4)
- [x] `fromKv` derivation over `KvStore`

## M1 — the code grant

- [x] Authorization endpoint, `code` only, PKCE mandatory (FR-C1, FR-C3)
- [x] Interaction suspend/resume (FR-I1, FR-I2) and remembered consent (FR-I4)
- [x] Token endpoint: `authorization_code`, `refresh_token`, with rotation and replay revocation
  (FR-C2, FR-T3, FR-T4)
- [x] Client authentication: `none`, `client_secret_basic`, `client_secret_post` (FR-C4)
- [x] UserInfo (FR-C5); `iss` in the authorization response (FR-C14)
- [x] `apps/demo-server` serves a real OP with reference login and consent screens

## M2 — storage and conformance

- [x] `oidcraft/adapters/drizzle` (SQLite) with real columns and indexes, passing the shared
  conformance suite; `explain query plan` asserts revocation and the user-code lookup use
  their indexes (FR-A5)
- [~] Postgres — deliberately not shipped untested; see the status section
- [x] `oidcraft/adapters/kysely`, passing the same conformance suite as memory and Drizzle
- [x] `metadata.test.ts`: the discovery document against OIDC Discovery 1.0 §3 and RFC 8414 §2,
  cross-checked against behaviour. **Not certification** — see `conformance/README.md`
- [x] `conformance/` harness: plan configuration and a runner, for a suite built from source
- [x] Run the OpenID Foundation suite locally: `basic` and `config` green (2026-09-30), with the
  deliberate refusals listed in `conformance/README.md`. The first run found six real bugs —
  the `acr_values` login loop, a non-URI `error_uri`, scope claims in the ID token, the broker
  ignoring UserInfo, JSON shown to the browser on an unredirectable error, and an http issuer
- [x] Run it in CI (NFR-C1): the suite's images, the forwarder in `conformance/compose.override.yml`,
  and `bun run conformance` as a job that fails the build
- [x] Checked `REQUIREMENTS.md` against the specs before the run (2026-09-30). Fixed: FR-C3's PKCE
  exemption, FR-T1's mandatory RS256, NFR-S2's loopback port, FR-C18's sector validation, and
  NFR-C1 dropping `dynamic` — see `conformance/README.md` for why
- [x] `oidcraft/runtimes/node` HTTP bridge, tested against a real node:http server (FR-R3)
- [x] Capability gating: mTLS methods are refused at construction where no certificate can be
  supplied, and absent from discovery (FR-R5, `G-8`)
- [x] Smoke tests for `oidcraft/runtimes/{bun,deno,workerd}`

## M3 — federation

- [x] `UpstreamProvider` discovery and the RP leg (FR-F1)
- [x] Handoff: single-use suspend/resume across the upstream round trip (FR-F3)
- [x] Home-realm discovery (FR-F4); linking policies (FR-F5)
- [x] Claim mapping (FR-F7); provenance carried on the identity (FR-F6)
- [x] Test upstream: a second oidcraft instance (ARCHITECTURE.md §10)
- [x] The authorization endpoint chooses the upstream (FR-F4) and the interaction carries that
  choice; the host still performs the round trip, because that part is I/O
- [x] Upstream back-channel logout mapped to the local sessions it produced (FR-F8)
- [x] `prompt`, `max_age` and `acr_values` passed through to the upstream (FR-F9)

## M4 — the rest of the protocol

- [x] Revocation, introspection (FR-C8); RP-initiated and back-channel logout (FR-C11)
- [x] DPoP (FR-C13): bound access and refresh tokens, `ath`/`htm`/`htu` checks, jti replay guard
- [x] DPoP nonces (`DPoP-Nonce`, `use_dpop_nonce`)
- [x] PAR (RFC 9126) and JAR by value (RFC 9101) (FR-C12)
- [~] JAR by reference — decided against in the core; see the status section
- [x] DCR (FR-C9) with RFC 7592 client management, gated by `onRegister`
- [x] Device grant (FR-C7) with slow-down enforcement; pairwise subjects (FR-C18)
- [x] Token exchange (FR-C2), gated on an explicit `exchangePolicy`; RAR (FR-C15) with declared
  types; step-up (FR-C16) forcing re-authentication for an unmet `acr`
- [x] CIBA (FR-C17), poll and ping

## M5 — batteries

- [x] Reference login and consent screens (FR-I3), remembered consent (FR-I4)
- [x] The remaining screens: account selection, upstream selection, device code, logout
- [x] Management API (FR-M1) over clients, grants, sessions, keys and identities, with audit
  events (FR-M3) — functions, not routes, so the host authorizes it
- [x] Admin UI (FR-M2): clients table and key list, `@vuetify/v0`'s `createDataTable` for
  sort/filter/paginate and its `Dialog` for the destructive confirmation
- [x] Admin: sessions and grants by account, with revoke and end-session
- [x] Admin: upstream providers shown read-only, since they are deployment configuration
- [x] First manual publish: `oidcraft@0.0.1` claimed the name — the similarity check cleared
- [x] `npm trust github` registration, so releases publish from CI (ARCHITECTURE.md §11) — registered
  2026-10-31 for `Fl0r14n/oidcraft`, `publish.yml`. Nothing published from CI yet: the first release
  run is the real test
- [x] The npm org `oidcraft`, claimed 2026-10-31. Nothing is published under it yet; owning it is what
  keeps `@oidcraft/core`, `@oidcraft/client` and `@oidcraft/ui`, the names this workspace keeps
  unpublished, from being published by anyone else
- [x] ~~First real release of `oidcraft`~~ — superseded 2026-11-11: the move below comes first, so the
  first real release is `@oidcraft/provider@0.1.0`, and `oidcraft` stays the 0.0.1 placeholder. Its
  trusted publisher, registered 2026-10-31, is never used

## The move to the `oidcraft` npm org (done 2026-11-11)

Decided 2026-10-31, postponed, then brought forward 2026-11-11 to before the first real release —
the provider and the client libraries go out together under one scope:

| was                                                     | is                     |
| ------------------------------------------------------- | ---------------------- |
| `oidcraft`                                              | `@oidcraft/provider`   |
| `vue-oidc`                                              | `@oidcraft/vue`        |
| `react-oauth-oidc`                                      | `@oidcraft/react`      |
| `ngx-oauth`                                             | `@oidcraft/angular`    |
| `@oidcraft/core`, `@oidcraft/client` (bundled, private) | published dependencies |

npm has no rename and no redirect, so this is a set of new packages and a deprecation of the old ones:

- [x] Rename in the workspace, 2026-11-11: `packages/server` is `packages/provider`, published as
  `@oidcraft/provider`; manifests, import specifiers, `--filter` names in scripts and
  CI, `verify-entries.ts`, tsdown `neverBundle` lists, `publish.yml`'s tag map, CLAUDE.md and the
  READMEs, which say which old name each binding continues. The brand, `OIDCRAFT_*` variables,
  client ids and this file's history keep `oidcraft` and the old names. The provider goes from 0.0.1 to 0.1.0, beside `core` and `client`; the bindings keep 7.0.0, 2.0.0 and 9.0.0, continuing
  their old names' majors
- [x] `@oidcraft/core` and `@oidcraft/client` published rather than compiled in, 2026-11-11: each is a
  `workspace:^` dependency of its consumers and external in every tsdown build. `verify-entries.ts`
  now fails an import `package.json` does not declare and a compiled-in copy, and the provider's
  still refuses `@oidcraft/client`. NFR-D4 reads "zero _third-party_ runtime dependencies", and
  ARCHITECTURE.md §2.1, §2.2 and §11 are rewritten. `publish.yml` packs with `bun pm pack`, which
  rewrites `workspace:^`, and uploads the tarball with `npm publish`, which does not
- [x] First publish of each scoped package by hand, 2026-11-11, from `5f17741`, in dependency order:
  `@oidcraft/core@0.1.0`, `client@0.1.0`, `provider@0.1.0`, `vue@7.0.0`, `react@2.0.0`,
  `angular@9.0.0`, all public. The tarballs came from `bun pm pack` and were installed into a fresh
  project and imported before going up. The account has 2FA on publish, so a manual publish needs the
  owner at the keyboard. Never a bare `npm publish`: it ships `workspace:^` verbatim
- [x] `npm trust github @oidcraft/<name> --repo Fl0r14n/oidcraft --file publish.yml --allow-publish`
  for each of the six, 2026-11-11, so releases tagged `@oidcraft/<name>@<version>` publish from CI.
  Not yet exercised: the first such release is the real test of `publish.yml`
- [x] `npm deprecate` the old names, pointing at the new ones, 2026-11-11, every version of each:
  `oidcraft` (a placeholder with no users), `vue-oidc`, `react-oauth-oidc`, `ngx-oauth`. Their
  published versions keep working
- [x] Archived the old `vue-oidc`, `react-oauth` and `ngx-oauth` repositories, 2026-11-11, each with a
  README note naming its `@oidcraft/*` package and pointing at `packages/<dir>`. Done: the move is
  complete; what remains is the first CI release, which tests `publish.yml`
- [x] Docs site — live 2026-11-11; what it found is under its requirements below
- [x] `oidcraft/accounts` (FR-I7): passwords through an injected argon2id hasher (`bunPasswordHasher`,
  `nodePasswordHasher`, interoperable PHC strings), TOTP with sealed secrets, recovery codes,
  throttling, reset tokens and sign-up, over a new `credentials` store in every adapter and SQLite
  migration `0002`. The demo's screens for it are next
- [x] Drizzle v1: the adapter targets `drizzle-orm@>=1.0.0-rc.5` (peer), typed on `SQLiteAsyncDatabase`,
  which a v1 `drizzle({ client })` satisfies without a cast. 0.45 is no longer supported
- [x] `oidcraft/adapters/typeorm` (FR-A6) on the shared conformance suite, tested on `sql.js`. The schema is
  the shared SQLite one, as `OIDCRAFT_ENTITIES` and `TYPEORM_SQLITE_MIGRATIONS` (forward-only classes
  TypeORM's own `runMigrations` applies). `orIgnore` cannot say whether it wrote, so insert-if-absent
  inserts and treats a failure as a lost race only when the colliding row exists

## MCP authorization (2026-07-28)

What the current MCP revision asks of an authorization server, checked against its text rather than
an earlier one.

- [x] Resource indicators (RFC 8707, FR-C19): a configured resource becomes the token's only audience,
  and only its resource server may introspect it. RFC 9728 metadata is built for it to serve
- [x] `application_type` at registration; a `native` client may register `http://localhost` (NFR-S2)
- [x] Client ID Metadata Documents (FR-C20) through a host-supplied resolver, with the consent screen
  showing the client's host and where the person returns
- [x] The demo server as an MCP authorization server: a configured MCP resource and a resolver
- [x] An end-to-end run with a real MCP client against the demo, rather than only this suite's tests
  — OpenCode 2.2.1, 2026-10-31, signing in through Chrome. It followed the 401 to RFC 9728 and RFC 8414
  metadata, chose a Client ID Metadata Document (`https://opencode.ai/oauth/opencode/client.json`) over
  registration, sent PKCE S256 and `resource` on authorization, code and refresh, and returned to a
  loopback IP with an ephemeral port. It found one bug, fixed: a resource's named server could not
  introspect that resource's tokens without also holding the broad FR-C8 `resourceServer` flag

## Adapter typing and the brokering rename

Before Postgres, which would otherwise be built on the old names. `createBroker` and
`createAccounts` take any `Adapter` today, so one without `identities` or `credentials` compiles and
threw on first use (in `link.ts`). The fix is a requirement at those entry points, not a
split of `Adapter`: making it the full set would turn `ProviderConfig` into a union, give the
management API a conditional type and flip what `Adapter` means, all to move one check
(`upstreams`, config.ts:350) that construction already catches.

- [x] `Adapter` unchanged: the seven required stores, `identities`/`credentials`/`realms` optional.
  Beside it, `BrokeringAdapter` (`identities` and `sessions.findByUpstreamSession` required),
  `CredentialsAdapter`, `RealmsAdapter`, and `FullAdapter` as their intersection
- [x] `createBroker` takes a `BrokeringAdapter`, `createAccounts` a `CredentialsAdapter`;
  `createProvider` keeps `Adapter` and its construction-time check for `upstreams` (NFR-D2).
  The guard in `link.ts` goes, since the type now makes it unreachable
- [x] The first-party adapters (memory, `fromKv`, Drizzle, Kysely, TypeORM, Redis) return
  `FullAdapter`, and their `federation: boolean` option goes: an adapter that omitted `identities`
  would make that type a lie, and an unused store costs an empty table. The demo's realms stop
  passing `federation: false`
- [x] Optional methods tied to `features.*` flags (`findByUserCode`, `prune`, the client writes and
  `list`) stay optional with their construction-time checks; typing each flag would make
  `ProviderConfig` a union per flag
- [x] "Federation" means OpenID Federation 1.0 (`G-1`, ARCHITECTURE.md §5.1), so brokering stops using
  the word: `oidcraft/federation` → `oidcraft/broker`, `FederatedIdentity`/`FederatedIdentityStore` →
  `LinkedIdentity`/`LinkedIdentityStore`, `FederationCallback` → `BrokerCallback`, and the
  `src/federation` directory with them. The table stays `oidc_identities`. CLAUDE.md, ARCHITECTURE.md
  §2.1 and §5, `verify-entries.ts` and `exports.test.ts` name the entry and move together
- [x] ARCHITECTURE.md §4: `Adapter` is what a custom adapter implements; the feature types are what
  an entry point requires
- [x] Landed 2026-10-30. The demo's upstream callback stays at `/federation/callback`: it is the
  redirect URI registered with Google (`.env.example`), and renaming a URL people have registered
  breaks their sign-in for a word. The new types found the demo handing `provider.config.adapter`
  (a plain `Adapter`) to the broker; it now passes its storage, which is a `FullAdapter`

## Refresh tokens and FAPI 2.0

After the adapter typing, before Postgres. In order: `dpop_jkt` and session-bound refresh tokens stand
on their own; the profile builds on both.

- [x] `dpop_jkt` (RFC 9449 §10): the authorization request carries the DPoP key's thumbprint, or a
  proof on the PAR push supplies it (§10.1); the code remembers it, and only a proof by that key
  redeems it, checked before the consume so a thief's attempt does not burn the code. No discovery
  metadata: RFC 9449 defines none for it. Landed 2026-10-30
- [x] Session-bound refresh tokens (FR-T6): issued without `offline_access` to a client with the
  `refresh_token` grant, expiring no later than the session, refused once it ends. Rotating as ever.
  Code grant only: a device or CIBA approval's session is the approver's browser. Landed 2026-10-30
- [x] The FAPI 2.0 profile (FR-C21), opt-in per provider or per client, refusing everything that
  requirement lists. Most of it is checks on what already exists: `requirePushedAuthorizationRequests`,
  the assertion audience in `clients/assertion.ts` (the issuer only; outside the profile the token
  endpoint URL stays accepted, because OIDC Core §9 says the audience SHOULD be it),
  the `iat`/`nbf` window, `application_type` for `http` redirects
- [x] FR-T3's exception: under the profile a refresh token is not rotated, still expires and is still
  revoked with its grant. The only place rotation is skipped. A public client cannot be under a
  provider-wide profile at all, so the test that rotation is untouched is a per-client profile beside
  ordinary clients. Landed 2026-10-30, `src/profile/fapi.ts` (ARCHITECTURE.md §3.3)
- [x] The demo server stays mixed: its SPAs public as now, plus one seeded `fapi-demo` client under
  the profile — `private_key_jwt`, DPoP, PAR — driven by a small server-side script or route, since a
  FAPI client cannot be a browser app. DPoP only: Bun exposes no client certificate (G-8)
- [x] `OIDCRAFT_PROFILE=fapi2` starts the demo with the profile provider-wide, the way
  `OIDCRAFT_DB=memory` already sets up a conformance run, so the suite never meets discovery that
  has to describe public clients too
- [x] The OpenID Foundation FAPI 2.0 test plan in CI (NFR-C1), a second entry of the `conformance`
  job's matrix against the demo with `OIDCRAFT_PROFILE=fapi2`. Green locally 2026-10-30, 53 modules,
  5 REVIEW, 1 expected skip (conformance/README.md). Running it found, and this fixed:
  - FR-C21 had the profile _require_ `dpop_jkt`; FAPI 2.0 only has the server support it
  - a confidential client's refresh token was bound to its DPoP key, which RFC 9449 §5 says it is not
  - DPoP `htu` compared as a string; §4.3 ignores the query and fragment and the case of scheme and host
  - under the profile: a DPoP `iat` 10 s ahead refused, FAPI's algorithms not applied at UserInfo, and
    an assertion `aud` array holding the issuer accepted
  - the demo's TLS 1.2 accepted ciphers BCP 195 does not recommend, and its login had no Cancel

## Postgres (FR-A4)

After the adapter typing and rename above.

FR-A4 already promises Drizzle on Postgres and Kysely on Postgres; what shipped is SQLite only, and
the Drizzle adapter cannot even be handed a Postgres database (`DrizzleDatabase` is
`SQLiteAsyncDatabase`). It was once decided against as "a Postgres schema shipped untested"; the
point was _untested_, and the fix is testing it. When it lands, choosing
the dialect and how a realm is scoped (schema or database) is the host's, in `configure` (G-6).

- [x] `POSTGRES_MIGRATIONS` in `adapters/sql/postgres.ts`: the same ids and tables as
  `SQLITE_MIGRATIONS`, `bigint` milliseconds, JSON kept as `text` so every adapter serialises as
  today. Unqualified table names, so they land in whatever schema the host migrates into.
  Exported beside `SQLITE_MIGRATIONS` from the drizzle, kysely and typeorm entries
- [x] Kysely: coerce every `Millis` with `Number()` in the row mappers. `pg` returns `int8` as a
  string, and `new Date('1730000000000')` is an Invalid Date — a real bug on Postgres today
- [x] Drizzle: a `pg-core` schema with columns matching `POSTGRES_MIGRATIONS`, and an adapter that
  takes either dialect's tables. Drizzle binds a schema name when a table is _defined_, so the
  Postgres tables come from a factory, `postgresTables(schema?)`, or a realm cannot get its own
  schema. Same `./adapters/drizzle` entry: `pg-core` ships inside `drizzle-orm`, so no new peer
- [x] TypeORM: `TYPEORM_POSTGRES_MIGRATIONS` from the same statements. Its `millis` transformer
  already numbers a string `bigint`; `insertIfAbsent` gets a lost-race test on Postgres, where a
  failed insert would abort an enclosing transaction
- [x] The adapter conformance suite on Postgres for all three, on a `postgres` CI service with
  `POSTGRES_URL`, skipped without it — the pattern `REDIS_URL` already uses. `pg` as the one dev
  dependency: Kysely's `PostgresDialect`, `drizzle-orm/node-postgres` and TypeORM's driver all take it
- [x] Realm isolation, which is the G-6 claim: two schemas in one database, the suite on each, and
  nothing written through one visible through the other — via `withSchema`, `postgresTables(schema)`
  and TypeORM's `schema` option
- [x] ARCHITECTURE.md §4.2 (two migration sets) and §7.1 (a Postgres schema per realm as the
  example)
- [x] `OIDCRAFT_DB=postgres://…` in the demo server, a schema per realm (`realm_<id>`), through Drizzle on Bun.sql
- Landed 2026-10-31, on Postgres 19rc1 (the newest image; 19 is not released). Drizzle runs on both
  `pg` and Bun.sql. Both drivers return `bigint` as a string on 19 as on 17, so the Kysely conversion
  is needed either way; the conformance suite fails three tests without it

## Demo server

`apps/demo-server` is reworked into one coherent demo before the docs site, in this order. TOTP
waits on `oidcraft/accounts` (FR-I7).

- [x] Renamed from `apps/server`; screens are server-rendered Vue on a shared `src/ui`, the admin
  app uses the same components, and `screens.test.ts` pins the conformance browser's contract
- [x] `packages/ui`, private: the design (CSS variables, Public Sans served from the OP's origin, a
  guilloche band), the components and the screens, built per issuer by `createScreens` with its
  brand, theme and form URLs; a TOTP screen ready for FR-I7
- [x] Admin signs in through the OP itself with `vue-oidc`, replacing `OIDCRAFT_ADMIN_TOKEN`; the API
  introspects the token in-process and checks an allowlist this app owns (FR-M1). Restyled on
  `@oidcraft/ui`, whose `UiDataTable` and `UiDialog` now carry `@vuetify/v0`
- [x] Discovery swallowed `InsecureEndpointError`, so an http issuer without `allowInsecure` surfaced
  as "no authorizePath". It now rethrows that one and still survives outages. The three demos allow
  plain http against a loopback issuer only; demo-vue had also been building against a stale npm
  `vue-oidc@5.3.0` in its own `node_modules`, shadowing the workspace link
- [x] SQLite through the Drizzle adapter (`OIDCRAFT_DB`), so an enrolment survives a restart; conformance
  runs with `OIDCRAFT_DB=memory`. The adapters now ship their SQLite schema as `SQLITE_MIGRATIONS`
  (FR-A4 said they did; they did not), and the CI conformance build now includes `vue-oidc`, which
  the admin bundle needs at startup
- [x] `/account`: self-service as another client of the OP — TOTP enrolment with a QR code, recovery
  codes, password change
- [x] A TOTP step after the password, recording `amr: ['pwd', 'otp', 'mfa']` and `acr: mfa` (FR-C16); sign-up,
  forgotten password and reset screens
- [x] The device flow approves as the browser's signed-in account. Without one, `provider.device.signIn`
  starts a login interaction on the same screens (password, TOTP, sign-up) that returns to the
  code; `provider.session(request)` is how a host's own screens see who is signed in

## `FR-*` coverage

Every functional requirement in `REQUIREMENTS.md` as it stood on 2026-11-11 is implemented — the
ones the 2026-11-12 review added or tightened are listed, unticked, under that review — including the six that an audit
against behaviour — rather than against these checkboxes — found missing after the list said
otherwise: FR-C4's mTLS methods, FR-C5's signed and encrypted UserInfo, FR-C11's front-channel
logout, FR-C13's certificate-bound tokens, FR-C16's resource-server challenge, and FR-T2's JWT
access tokens.

`metadata.test.ts` exercises every advertised value rather than reading it, which is the check that
was missing when discovery advertised three things the code refused.

What is _not_ claimed: see the status section. Implemented is not the same as certified, and no
`FR-*` here has been checked by anything but its author and its tests.

## Next, in this order

1. ~~Fix what the server review found~~ — done 2026-10-13, every finding below. The review was by
   agents reading the code against REQUIREMENTS.md, so it narrowed the search rather than ending it.
2. ~~The conformance suite in CI~~ (NFR-C1) — the `conformance` job, pinned by `SUITE_VERSION`.
3. ~~Adapter typing and the brokering rename~~ — done 2026-10-30.
4. ~~Refresh tokens and FAPI 2.0~~ — done 2026-10-30, the FAPI 2.0 plan green in CI.
5. ~~Postgres~~ — done 2026-10-31, on Postgres 19rc1.
6. ~~The MCP demo, then a real MCP client~~ — done 2026-10-31, OpenCode calling a tool end to end.
7. ~~`npm trust`~~ — registered 2026-10-31, for the unscoped name the move below replaces.
8. ~~The move to `@oidcraft/*`~~ — done 2026-11-11: six packages published, trusted publishers
   registered, old names deprecated, old repositories archived.
9. ~~The docs site~~ — live 2026-11-11, every page its requirements listed.
10. ~~What the docs pages found~~ — fixed 2026-11-11, every item under _Found by the docs pages_,
    and released in `@oidcraft/provider@0.2.0`.
11. ~~Adapters as packages~~ — done 2026-11-11, ahead of 1.0: `@oidcraft/adapter` with
    `@oidcraft/drizzle`, `kysely`, `typeorm` and `redis` on it, released (below).
12. **What the 2026-11-12 review found** — below, in its order: security, then operations, then
    structure, then the client libraries.

## Review — 2026-11-12

One reader, the whole provider, the adapter contract, `fromKv`, the Kysely, Redis and memory
adapters, `core`, `client` and the three bindings; Drizzle only in outline, TypeORM and `@oidcraft/ui`
not at all. By reading, not by exploit: each item names where it was seen, and each fix starts with
the test that shows it. `REQUIREMENTS.md` was corrected first, the same day, so every item cites the
text it is held to. In fix order.

**Security**

- [x] A JWT access token's `jti` is a bearer credential: it is the stored artifact's id, and
  `resolveAccessToken` tries the presented string as an id before anything else, so a `jti` read from
  a resource server's log is a token. The JWT path decodes without verifying
  (`token/access-token.ts:138`). FR-T2, NFR-S11. Fixed: the JWT finds its record only once its signature
  verifies, and a record minted as a JWT is refused when its `jti` is presented bare
- [x] Nothing is hashed at rest but reset tokens: codes, access and refresh tokens, device codes, PAR
  references and registration access tokens are stored as themselves. One wrapper over
  `adapter.artifacts` in the provider, as `withClientMetadata` wraps `clients`, so the id is
  `sha256(value)` in and out: no call site and no adapter changes. Plain SHA-256, since every value is
  288 random bits; the device `user_code` stays as typed, being short enough that a hash hides
  nothing. A JWT's `jti` becomes the hash, which closes the item above. Live tokens stop working at
  the upgrade — free with no users, and never again. NFR-S11. Fixed in `src/artifacts.ts`; a
  registration access token is hashed on the client record and echoed back from the request. The
  wrapper could not be as transparent as planned: a device request found by its user code carries its
  stored id and cannot be written back, so the person's answer became a record of its own under the
  user code — which also takes the device half of the lost-approval item below
- [x] Found on the way: a replay revoked the grant at one moment, and a redemption racing it wrote its
  tokens the moment after, so they survived. The existing test passed on the order two promises
  happened to run in, which hashing changed. Fixed: both sides claim one replay-guard entry, and the
  redemption that finds it taken revokes again and fails (`token/code.ts`). NFR-S4
- [ ] Then client secrets, as their own step: `client_secret_basic` and `client_secret_post` compare
  against a stored hash, so `Client` changes shape and the admin shows a secret once, at creation.
  `client_secret_jwt` keeps the secret, as it must. NFR-S11
- [x] End-session takes the client from `client_id` and never compares it with the hint's `aud`; the
  verified claims are used only as a boolean, so a hint issued to one client redirects to another's
  URI and skips the confirmation. The hint's `sid`/`sub` are not compared with the browser's session
  (`session/end-session.ts:52`). FR-C11
  Fixed: the client is the hint's audience, a `client_id` beside it must name it, and a hint whose `sid` is not the browser's session asks first
- [x] A device or CIBA poll rewrites the whole artifact to record `lastPolledAt`, so an approval
  landing between its read and its write is overwritten with `pending` (`authorize/device.ts:104`,
  `authorize/ciba.ts:135`). Keep the poll clock in `replay.claim` and never write the artifact from
  the poll. FR-C7
  Fixed: the answer is a record of its own in both flows, so the poll's rewrite of the request cannot touch it; the poll clock stays on the request
- [x] Completing a password reset ends sessions and leaves `offline_access` refresh tokens working,
  since each carries its own sign-in (`accounts/index.ts:338`). FR-T7
  Fixed through the grants: every token an account holds carries one, so no contract change
- [x] Deleting a client leaves its access tokens answering at UserInfo and introspection until they
  expire, and its grants in place. There is no way to revoke by client: `ArtifactStore` needs one.
  FR-T7
  Fixed: `artifacts.revokeByClientId` and `grants.destroyByClientId` in the contract, in every adapter and in the conformance suite, with migration `0004_indexes`; `fromKv` scans for it, deleting a client being rare
- [x] Registration casts a stranger's JSON: a `null` body or a non-string `scope` is a `TypeError`
  and a 500, `jwks` is stored unread, `jwks` with `jwks_uri` is accepted
  (`clients/registration.ts:172`). The metadata-document path has the same casts. FR-C9
  Fixed: `objectFrom`, `stringFrom`, `stringsFrom` and `keysFrom` read both the registration body and a metadata document
- [x] `management.clients.update` checks only the FAPI profile: `requirePkce: false` on a public
  client is stored (the request path still refuses it), and a pairwise client with redirect URIs on
  several hosts is stored and then throws at the token endpoint. One `validateClient` for create,
  update and registration. FR-M1
  Fixed: `clients/validate.ts`, read by create, update and registration
- [x] Revoking a refresh token deletes the grant (`resource/revocation.ts:34`); FR-C8 now says the
  consent stays, as `Grant`'s own comment and ARCHITECTURE.md §4 always did. Only `/revoke` is
  affected: end-session never touched the grant
  Fixed
- [ ] One grant per account and client means one app on two devices shares it, so a revocation or a
  detected replay on one signs out the other. A family id on refresh tokens, and revocation and
  replay scoped to the family; FR-C8, FR-T3 and FR-T4 change with it. After the item above, not with it
- [x] A FAPI client's refresh token is never rewritten, so its idle lifetime never restarts and it
  dies 14 days after issue whatever its use (`token/issue.ts:74`). Rewrite the same artifact with a
  new expiry on each use, capped by the family's: one write, no contract change. FR-T3
  Fixed
- [x] `interactions.complete` consumes the interaction before its last check, so "consent without a
  signed-in account" burns it (`authorize/interactions.ts:98,133`). FR-I2
  Fixed
- [x] Discovery advertises `dpop_bound_access_tokens_required`, which is not registered metadata,
  keyed off `dpopNonces`, which means something else (`discovery.ts:86`). FR-C6
  Fixed: removed
- [x] Smaller, fixed: pairwise subjects are an HMAC over a JSON pair and the details-consent id a hash of
  a JSON triple, so a dot or a newline cannot move between the parts (FR-C18) — every pairwise subject
  changes; the session cookie carries the issuer's path in its name, so two issuers on one host no
  longer share it, and a root issuer keeps `oidcraft.sid`; UserInfo answers a bad token as
  `invalid_token`; the logout token is signed with the client's `id_token_signed_response_alg`
- [x] A DPoP nonce demand is a storage write a public client triggers unauthenticated. Decided against,
  2026-11-12: every DPoP proof already costs one write for its `jti`, the nonce rows live five minutes
  and are pruned, and a stateless nonce would put a new secret in the configuration of a feature that
  is off by default
- [x] UserInfo served a token whose audience is another resource, so the resource server holding it
  could read the profile. Refusing it alone would have left such a client no way to its claims, every
  token from that authorization being restricted (`audienceFor`). Fixed as FR-C5 now reads: refused at
  UserInfo, and the scope claims travel in the ID token of exactly those responses (OIDC Core §5.4).
  The conformance plans send no `resource`, so they see no change

**Operations**

- [x] No hook for an unexpected failure: `errorResponse` wraps it as `server_error` and the cause is
  gone (`errors.ts:104`). `onError` on the config. NFR-D5
  Fixed: `onError(error, { request })`, called for anything the provider did not mean, and never allowed to change the answer
- [x] The Redis adapter scans on request paths: `fromKv` answers `grants.findByAccountAndClient`,
  `sessions.listForAccount` and `findByUpstreamSession` with a prefix scan, and Redis `SCAN MATCH`
  walks the whole keyspace — on every `/authorize` that has a session. Index keys, as `user-code/` and
  `grant-index/` already are. Pinned by a test adapter whose `scan` throws through the authorization
  and token flows, which fails today on `fromKv`. NFR-P1
  Fixed in two parts, the contract untouched: `fromKv` scans one record's keys and never a family on a request path, pinned by a test that records the prefixes scanned; and `@oidcraft/redis` answers a prefix from its own sorted-set index of key names, kept by one script per write, pinned by a test that counts commands
- [x] Only artifacts can be pruned. Replay entries and sessions grow without bound on SQL, and the
  Kysely `prune` deletes a row at a time. NFR-P3
  Fixed: `sessions.prune` and `replay.prune` in the contract, the three SQL adapters and the conformance suite, with a session expiry index in `0004_indexes`. The sweeps still delete a row at a time: a composite key has no portable single-statement bounded delete across SQLite and Postgres
- [x] `clients.list(cursor, limit)` ignores both in every adapter read
  Fixed: client id order, the cursor the last id of a page, checked by the conformance suite
- [ ] A first consent from two tabs inserts two grants with different ids against a unique
  `(account_id, client_id)` index; the second is a 500. Upsert on that pair
- [x] `findByUserCode` and `findByUpstreamSession` do not filter expired rows where `find` does
  Fixed in `fromKv` and the three SQL adapters, and checked by the conformance suite

**Structure**

- [ ] `Artifact.payload` is `Record<string, unknown>` and the provider casts it about thirty times —
  the shape ARCHITECTURE.md §4.1 argues against. A payload type per kind, read and written through
  one function each; no adapter changes
- [ ] Device and CIBA are one state machine written twice: poll, slow-down, approve, deny. The
  grant merge is written three times (`interactions.ts:136`, `device.ts:202`, `ciba.ts:196`), and
  `device.ts:200` rewrites `session.clients` rather than calling the atomic `addClient`
- [ ] Signing is written four times — ID token, JWT access token, UserInfo, logout token — each
  reading the key store again. One `signerFor(config, client, alg?)`, one key read per response
- [ ] Duplicates: the client key set in `assertion.ts` and `request-object.ts`; the DPoP options in
  the token endpoint, PAR and UserInfo; `MTLS_METHODS` in `config.ts` and `discovery.ts`;
  `noAccounts` in each adapter; about 150 lines of row mapping in each SQL adapter, which belong in
  `@oidcraft/sql`
- [ ] CORS works out the client again after the handler did, cloning the body twice and reading the
  client store, and at UserInfo the artifact, a second time. The handler returns the client it resolved
- [ ] `RequestContext` carries an `issuer` that `dispatch` overwrites, so every runtime entry's
  `issuer` argument does nothing, and a `clientIp` `handle` never reads while the device rate limit
  takes it separately
- [ ] `ProviderConfig.interactionUrl` is typed optional and required at construction, which leaves
  dead checks in `provider.ts`, `device.ts` and `ciba.ts`
- [ ] Dead: `IdTokenInput.code` and `.claims`, the exported `ClientAuthenticationInput`. Detached doc
  comments at `binding/dpop.ts:7`, `authorize/request-object.ts:8`, `adapter/src/types.ts:125`

**Required and not built**

- [ ] FR-F8: RP-initiated logout does not propagate upward; nothing in the broker builds the
  upstream's end-session request
- [ ] NFR-S12: the README does not yet say which limiting is the host's
- [ ] `G-9`: failed sign-ins counted per account and address — five lock that address out of that
  account — with a ceiling of about fifty per account across all addresses. `authenticate` and
  `verifySecondFactor` take an optional `clientIp`; without one, today's per-account lock. The
  reference screen answers a locked account as it answers a wrong password. FR-I7

**Client libraries** (FR-L\*, new)

Read: `core`, `client`, and each binding's instance and reactive layer; their 329 tests pass. The
shape is sound — one protocol, one stateful runtime, three thin views, no ambient instance. What the
new requirements ask that the code does not yet do:

- [ ] One refresh per instance, not per browser: two tabs refreshing the same token is a replay to a
  rotating provider, this one included, and revokes the grant. `navigator.locks` around the refresh,
  re-reading storage inside the lock. FR-L5
- [ ] Failures are strings on a token-shaped object, and a request that failed is `undefined`; the
  broker tells them apart by matching `'Invalid nonce'` and by a missing ID token
  (`broker/broker.ts:47`). A typed result from `completeAuthorization`. FR-L2
- [ ] Smaller: a token is refreshed only after it has expired, so the request at the boundary fails;
  `logout` with a redirect does not revoke the refresh token; the callback leaves the code in the
  address bar

## Server review — 2026-10-10

Four parallel reviews of `packages/server`, every critical and high finding re-read against the code.
In fix order; the first is the only one that changes the adapter contract.

**Critical**

- [x] Single use is not atomic anywhere. `consume()` returns nothing and every adapter writes
  unconditionally; `replay.claim()` reads then writes. Two parallel redemptions of a code or
  refresh token both succeed and nothing is revoked (FR-T3, FR-T4, NFR-S4, NFR-S5). Covers
  codes, refresh tokens, PAR `request_uri`, device and CIBA approvals, assertion and DPoP `jti`.
  Fixed: `consume` and `claim` return whether this caller won, `KvStore` gained an atomic `insert`,
  and an artifact upsert can no longer revive a consumed one — a second hole the fix found,
  reachable through a device or CIBA poll writing back a stale read. Interactions and the
  federation handoff are now consumed too.

**High — security**

- [x] JAR merges unsigned outer parameters into the signed request; PKCE can be injected (RFC 9101 §5)
- [x] `authorization_details` issued without consent, and absent from `InteractionRequest` (FR-C15)
- [x] DPoP nonce can be minted by the client: `claim` stores the unknown value it refuses (RFC 9449 §8)
- [x] Client assertion lifetime measured from the client's `iat`; jti remembered for 300 s only (FR-C4, NFR-S5)
- [x] Federation handoff not bound to the browser — login CSRF (FR-F3). `apps/demo-server` now brokers
  to Google when `UPSTREAM_GOOGLE_*` is set, so the round trip and its cookie run for real
- [x] workerd hands over an empty certificate DER; every thumbprint is the same (FR-C13).
  Fixed: `ClientCertificate` carries the `x5t#S256` thumbprint, not the DER. Workers never see
  the DER, so workerd derives it from `certFingerprintSHA256` and drops a certificate without one
- [x] Open registration does not validate `grant_types` (FR-C9). Fixed: only grants discovery
  advertises, no `client_credentials` for a public client, and `response_types` must agree

**High — broken features**

- [x] CIBA ping can never redeem; `ciba.test.ts` asserts the bug (FR-C17). Fixed: a ping client
  redeems with the poll request (CIBA §10.2). Ping end to end: `Client` carries the
  notification endpoint, registration sets the mode and endpoint, and `ciba.resolve` returns the
  `CibaPing` the host delivers
- [x] A PAR-required client cannot finish an interaction: the replay drops `request_uri` (FR-C12).
  Fixed: a pushed request resumes through a fresh pushed reference, never the front channel
- [x] Logout notifies only the first RP: `session.clients` is never appended (FR-C11). Fixed in
  `issueTokens`, so code, device and CIBA all record the client, through `SessionStore.addClient`,
  which every adapter makes atomic (a key per client over a `KvStore`, compare-and-swap in SQL)
- [x] JWT access tokens cannot be revoked or introspected (FR-C8, FR-T2). Fixed: both resolve by `jti`
- [x] mTLS: binding only on `authorization_code`, lost on refresh; client auth only at the token endpoint (FR-C4, FR-C13).
  Fixed: every grant takes one `Binding` (DPoP key and certificate); a refresh rebinds to the
  certificate presented, and a public client's refresh token is held to its certificate
  (RFC 8705 §4). PAR, device, CIBA, revocation and introspection receive the certificate

**Medium**

- [x] Device/CIBA tokens carry requested, not approved, scopes; approvals not checked against the requested user.
  Fixed: `checkApproval` — approved ⊆ requested, keeps `openid`, session is the approver's, CIBA approver is the hinted user
- [x] Refresh narrowing consumes the refresh token without reissuing; withdrawn grant scopes return.
  Fixed: the rotated refresh token keeps its own scope (RFC 6749 §6), intersected with the grant
- [x] Pairwise `sub` leaks via logout token, introspection, exchange; UserInfo lets the account store override it (FR-C18)
- [x] Token exchange: drops sender binding, extends lifetime, mislabels token types (RFC 8693). Fixed, and only
  access and refresh tokens are exchanged or issued: an ID token is not stored
- [x] `form_post` advertised but answered in the query; error redirects ignore `response_mode`; `access_denied` lacks `iss` (FR-C14).
  Fixed: one `authorizationResponse`; an interaction error is delivered through `/authorize?response=` once
- [x] `max_age=0` loops; `prompt=select_account` ignored; `prompt=none` combined accepted (FR-I5)
- [x] No `user_code` rate limiting (NFR-S3); Node bridge takes the left-most `X-Forwarded-For`. Fixed: 5 wrong codes
  per address per 10 minutes (50 when the host passes no address); the right-most forwarded entry
- [x] DPoP `htu` from `request.url`, not the issuer (NFR-S6); an issuer with a path 404s every route
- [x] Upstream back-channel logout tokens: no jti replay, no `typ`, unchecked `events`
- [x] Construction accepts a missing `interactionUrl`, CIBA without its resolver, federation without its stores (NFR-D2)
- [x] No CORS, so a browser client on another origin cannot use the OP. Fixed: by registered redirect origins (ARCHITECTURE.md §3.1)
- [x] End-session rejects an expired `id_token_hint`; a bare GET logs out without confirmation. Fixed: a `logout`
  interaction kind; the reference app's confirm screen is now that interaction
- [x] Introspection has no resource-server authentication; `iat` equals `exp` (FR-C8). Fixed: `Client.resourceServer`;
  `iat` recorded at issuance
- [x] A malformed cookie or Basic header is a 500
- [x] RFC 7592 update skips `onRegister`, resets `requirePkce`, compares the token with `!==`. Fixed: `onRegister`
  runs on update with `{ existing }`, and its answer decides the exemption
- [x] Non-string request-object claims become `"[object Object]"`

**Low and cleanup**

- [x] `at_hash` always SHA-256; no `sid` in the ID token; an ID token without `openid`
- [x] Refresh family has no absolute lifetime; offline access dies with the browser session. Fixed:
  `ttl.refreshTokenFamily` (90 days); a refresh token carries its sign-in and outlives the session, not the grant
- [x] Registration: unvalidated logout and `jwks_uri` URIs (SSRF), http `localhost` (NFR-S2). A name that resolves to a
  private address is still the host's to refuse: only it resolves
- [x] Discovery advertises the wrong algorithm lists. Fixed: `keys/algorithms.ts`, one list for verification and discovery
- [x] Claim mapping can pair one source's `email_verified` with another's `email`; `acr`/`amr`/`sid` unprotected
- [x] Access-token artifacts built in three places; `step-up.ts` belongs in `resource/`

**Follow-ups, not findings**

- [x] A Redis `KvStore` (Bun's built-in client), at least in tests: nothing exercises `fromKv` over a
  distributed store, where `insert` being atomic is the whole point — the memory store is atomic
  for free. Possibly an `oidcraft/adapters/redis` entry once it exists.

- [x] `bun check` is every `typecheck`; SFC packages (`vue-tsgo`) and the Angular island (TypeScript 6)
  put their real checker in a `check` script, which `bun check` runs. `engines.bun` is `>=1.4.4`

## Docs site — requirements

Started 2026-11-11 as `apps/docs`, VitePress (ARCHITECTURE.md §8.5). Done so far:

- [x] The site, rendering `REQUIREMENTS.md`, `ARCHITECTURE.md`, `PLAN.md` and the package READMEs by
  `@include`, not by copy
- [x] The landing page with the status in the hero: the plans that pass, not certified, not in production
- [x] The id spine: every defined id anchored, every mention linked, and `reference/ids` listing the
  files and tests citing each one, read at build time — 75 of the 85 ids are cited
- [x] Local search, dark mode, "tracks `main`" in the footer, and `docs.yml` deploying to GitHub Pages
  on every push to `main`
- [x] GitHub Pages on, source "GitHub Actions", 2026-11-11: live at https://fl0r14n.github.io/oidcraft/
- [x] A React page, from a new `packages/react/README.md` — the package had none, so its npm page
  would have been blank too
- [x] The seven pages below, 2026-11-11: the interaction contract, storage adapters, runtime
  deployment, security posture and coming from `oidc-provider` under `guide/`; the configuration and
  error references under `reference/`, generated from the source. Every sample is a region of a test
  in `apps/docs/samples/` (25 tests). Writing them found the defects listed next

### Found by the docs pages (2026-11-11)

Confirmed against the code. The unticked ones are open, each needing a decision.

- [x] **`prompt=consent` was dropped after a login**, fixed 2026-11-11: `authorizationUrl` deleted
  every `prompt` value when it resumed the request, so an account already holding a covering grant
  signed in and was never asked (FR-I5, OIDC Core §3.1.2.1). Now a finished interaction removes only
  the prompts it answered — a login `login` and `select_account`, a consent `consent` — so the replay
  still cannot loop and nothing it did not answer is skipped. Three `flow.test.ts` cases; the first
  fails without the fix
- [x] **`@oidcraft/provider/runtimes/node` could not load on the Node it claimed**, fixed 2026-11-11:
  it imports `argon2` from `node:crypto`, which exists from Node 24.7, while `engines` and FR-R3 said
  Node ≥ 22 — a load-time `SyntaxError` there, taking `toNodeHandler` down with
  `nodePasswordHasher`. Reproduced on Node 22.23.4 against the published 0.1.0. Fixed by raising the
  floor rather than working around it: every package's `engines` and FR-R3 say Node ≥ 24.7 (24.0–24.6
  lack `argon2` too), and CI imports every server-side entry on Node 24.7
  (`scripts/load-entries.mjs`), so the floor stays tested
- [x] The adapter conformance suite, usable outside this repo, 2026-11-11: the fourteenth entry,
  `@oidcraft/provider/adapters/conformance`, returns 28 `{ name, run }` checks that throw, so any
  runner wraps them; `verify-entries.ts` refuses a runner import. Checks for `identities`,
  `credentials` and `realms` run only for the stores `implements` names, so a core-only adapter
  fits. Every first-party suite runs it through `bun-conformance.ts` (272 tests on SQLite, Postgres
  and Redis), and the adapters page runs it against its own `Map`-backed `KvStore`. Ships with the
  next `@oidcraft/provider` release
- [x] Interaction completion checks the host's answer, 2026-11-11: `complete` refuses a login naming
  an account the `AccountStore` cannot find (FR-I2) and a consent naming a scope the request did not
  ask for (FR-I4), before consuming the interaction. The `acr` a login reports stays the host's word:
  the host is the authenticator, and the `claims` parameter, where an essential `acr` would be
  enforceable, is not implemented
- [x] Consent is all or nothing, explicitly, 2026-11-11 (decided): an answer leaving out a requested
  scope not already granted is refused rather than stored and asked again, and FR-I4 says so.
  Device and CIBA approvals (`authorize/approval.ts`) follow the same rule since: an approval covers
  every requested scope or is `{ denied: true }`. A client that asks for a scope gets it or nothing,
  never a token missing what it needs to work
- [x] mTLS on Node, 2026-11-11: `ClientCertificate.verified` is required, and `nodeContext` supplies
  every presented certificate with it, its subject and issuer as RFC 4514 names. `tls_client_auth`
  needs `verified` and compares the subject as a name (RFC 4517 `distinguishedNameMatch`);
  `self_signed_tls_client_auth` and bound tokens do not need it. Checked over real TLS on Node 26;
  `bun test` cannot do that (G-8), so the context's own tests carry real certificates on a stub socket.
  Still not done: the SAN forms of `tls_client_auth`, and a certificate forwarded by a proxy in a
  header. `capabilities.clientCertificate` stays the host's declaration, deliberately
- [x] Smaller, 2026-11-11: `interaction_required` and `account_selection_required` removed, as nothing
  could raise them; registration answers `invalid_redirect_uri` and `invalid_client_metadata`
  (RFC 7591 §3.2.2); 56 error sites gained a clause (NFR-D3), leaving the eight `server_error`s and
  the 404/405 refusals without one on purpose; token exchange answers `invalid_request` as RFC 8693
  §2.2.2 requires; a `request_uri` with PAR off is `request_uri_not_supported`; `prompt=none` no
  longer suspends when an authorization-details approval was spent; FR-I7 and FR-A2 corrected; the
  Deno and workerd entries export their argument types

The requirements, as recorded before it started:

**Samples are executed, never written.** Every code block comes from a file the test suite runs and
is extracted at build time, the way `minimal.test.ts` already does for the README example. A rotted
sample in a charting library is an annoyance; in an auth library it is a security instruction that
no longer holds.

**The landing page says what is not done.** "Passes the OpenID Foundation `basic` and `config`
plans; not certified. Not used in production" belongs above the fold, not in a FAQ. Docs sites are where that discipline erodes
into "production-ready" and a grid of green ticks, so this is an acceptance criterion rather than an
intention. If the site cannot say it on page one, it is not ready to exist.

**The requirement ids are the spine.** There are 85 `FR-*`/`NFR-*`/`G-*` ids and 75 of them are
cited in the source. `FR-C3` should be a link — to the requirement, to where it is implemented, to
the test that proves it. That is the thing no other provider's documentation has, and the content
already exists.

**It renders the existing files; it must not fork them.** `ARCHITECTURE.md`, `REQUIREMENTS.md` and
`PLAN.md` stay the source. Two copies of a requirement is strictly worse than one.

Pages that do not exist yet and have to be written:

- The interaction contract — every integrator implements login and consent, and it is currently only
  described in `FR-I*`. This is the page that decides whether someone succeeds.
- Adapter authoring: `KvStore` in five methods (one atomic insert), or the full `Adapter`, and how to run the shared
  conformance suite against your own.
- Configuration reference, generatable from the `.d.mts`.
- Error reference: each OAuth error, what causes it, which clause.
- Security posture: the non-negotiables with their reasons — PKCE, rotation, replay revoking the
  grant, exact redirect matching — and the known gaps, `G-8` among them.
- Runtime deployment: what differs across Bun, Node, Deno and workerd.
- Coming from `oidc-provider`, including where it is still the better choice.

Mechanics: search, dark mode, built and deployed by CI to GitHub Pages — docs built by hand stop
being built — and either versioned docs or a plain statement that they track `main`, since the API
will churn at `0.0.x`.

**Decided 2026-11-11: VitePress**, with its Vite contained in `apps/docs` — the deliberate break from
ARCHITECTURE.md §1.1, recorded in §8.5. Starlight was the alternative had Vue needed to stay out of
the docs toolchain; it did not.

## Adapters as packages

Landed 2026-11-11, ahead of 1.0 at the user's call: the provider stays `0.x` (`0.2.0`, since `0.1.0`
is on npm with the `./adapters/*` subpaths this removes) and the new packages start at `0.1.0`. The
shape and why are ARCHITECTURE.md §2.1.

- [x] `@oidcraft/adapter`: `Adapter`, the stores and the records, `fromKv`, the memory adapter
  (`./memory`), the suite (`./conformance`). The key stores and
  `ConfigurationError` moved with it, because the memory adapter generates keys when given none;
  the provider re-exports the types and `ConfigurationError`, not the helpers
- [x] `@oidcraft/drizzle`, `@oidcraft/kysely`, `@oidcraft/typeorm`, `@oidcraft/redis`, each peering on
  `@oidcraft/adapter` (and a `devDependency`, so `bun run --filter` builds the contract first) and
  never on the provider; each with its own `verify-entries.ts`
- [x] The provider: eight entries, no peers, `@oidcraft/adapter` a dependency. Its `verify-entries.ts`
  now fails on any storage library in any entry
- [x] The migrations are `@oidcraft/sql`, private, with `./sqlite`, `./postgres` and `./testing` (the
  Postgres schemas for tests); Drizzle, Kysely and TypeORM each compile in its built `dist`. Only
  those three read it, so it is not contract
- [x] The adapters' tests run the suite the way the docs tell a third-party adapter to, one
  `test(check.name, check.run)` per check, so no test imports across package folders
- [x] `publish.yml`, `load-entries.mjs`, the demo and the docs on the new names. FR-A6 and NFR-D4
  reworded: they named the subpaths
- [x] Released 2026-11-11: `@oidcraft/core@0.2.0` and `@oidcraft/provider@0.2.0` from release tags
  through `publish.yml`, with provenance; `@oidcraft/adapter`, `drizzle`, `kysely`, `typeorm` and
  `redis` at `0.1.0` published by hand. A fresh install from npm loads every entry on Node and serves
  discovery from a provider on `@oidcraft/adapter/memory`
- [x] Trusted publishing for the five new packages, 2026-11-11, so their next release is a release tag
  through `publish.yml`, like the rest
- [x] The client's identity declared once, in `@oidcraft/core`: `ClientCredentials`, `ClientAuthMethod`
  (with `TokenAuthMethod` derived from it), and `tokenAuthMethod` renamed `tokenEndpointAuthMethod`
  everywhere, core included, so core goes to `0.2.0`. `@oidcraft/adapter` depends on core for it

## `tls_client_auth` by SAN (RFC 8705 §2.1.2) — planned

Planned 2026-11-11, not started. Today a `tls_client_auth` client can only register
`tls_client_auth_subject_dn`. RFC 8705 §2.1.2 allows exactly one of five: the subject DN, or a
`tls_client_auth_san_dns`, `_san_uri`, `_san_ip` or `_san_email` entry the certificate must carry.

- [ ] `Client` in `@oidcraft/adapter` gains `tlsClientAuthSanDns`, `tlsClientAuthSanUri`,
  `tlsClientAuthSanIp`, `tlsClientAuthSanEmail`. Clients are stored as JSON, so no migration; a
  minor release of `adapter` and the provider, none of the four adapters
- [ ] `ClientCertificate` gains `sanIps` and `sanEmails` beside the existing `sanDnsNames` and `sanUris`
- [ ] `./runtimes/node` fills all four from `X509Certificate.subjectAltName`, which quotes a value
  containing a comma, so it is parsed rather than split
- [ ] `binding/mtls.ts` matches each type as it compares: DNS case-insensitive, an IP normalised (one
  IPv6 address has many spellings), an email's domain case-insensitive and its local part exact, a URI
  exact. Still only on a `verified` certificate (FR-R4)
- [ ] Registration (DCR, RFC 7592, the management API) accepts the four, refuses a client with none
  or more than one of the five, and echoes them; `fapiClientProblems` applies the same rule
- [ ] Workers expose the subject and issuer but no SANs, and Bun no certificate (G-8): construction
  refuses a SAN-registered client where the runtime cannot supply SANs, as FR-R5 already does for
  the mTLS methods where no certificate can be
- [ ] Tests: each comparison, the exactly-one rule, and Node over real TLS with a certificate per SAN
  type, as the subject-DN case is tested today. FR-C4 names the five registrations

Not in it: a certificate forwarded by a proxy in a header, which G-8 decided against until an
mTLS-only deployment on Bun needs it.

### Upstream Bun, checked 2026-11-11

Nothing tracks exposing the client certificate to a `Bun.serve` handler: no issue, no PR. The only
movement is on `node:https`: oven-sh/bun#16834 (its `req.socket` is not a `TLSSocket`) has a fix
open, oven-sh/bun#37255, which adds `getPeerCertificate()` to it. Open, unreviewed and in conflict
with `main`, last touched 2026-11-06. If it lands, mTLS works on Bun through `./runtimes/node`'s
`toNodeHandler` on a `node:https` server, not through `Bun.serve`, and G-8's re-verification is the
first thing to repeat.

## Decisions waiting on an answer

None.

Decided 2026-11-12, with the review: **FR-C8** revoking a refresh token revokes its grant's tokens and
keeps the consent; only `grants.revoke` removes consent · **FR-T3** a FAPI client's refresh token
restarts its idle lifetime on each use, within the family's · **FR-F4** an `acr_values` entry naming
an upstream is an instruction and comes before the email domain, which is an inference; no per-step
switches, since leaving out `domains` or narrowing the client's list already does it · **FR-F10,
NFR-S9** retained upstream tokens go to the host and the library stores none; a store of its own
only if a deployment asks · **NFR-S11** everything bearer hashed at rest, artifacts first and client
secrets as a second step · **NFR-P1** no scan on a request path, in place of "at most two round
trips" · `G-9` failed sign-ins counted per account and address, with a higher ceiling per account.

Decided earlier: `G-3` FAPI 2.0 as an opt-in profile (FR-C21), with FR-T3's exception for its clients · `G-1` OpenID Federation 1.0 not planned unless a deployment needs it · `G-4` upstream SAML
not in-tree · `G-6` storage per realm, never shared tables · `G-8` mTLS unavailable on Bun until Bun exposes the certificate.

## Federation moved off `openid-client`

Landed 2026-09-18. `oidcraft/federation` is now a relying party through `packages/core`, this
workspace's own RP core, and `openid-client` is gone from the peers. That package is **private and
never published** — it is bundled into the `./federation` entry, so `dist/federation.mjs` imports
`oidcraft` and `jose` and nothing else, and NFR-D4 is literally true again (ARCHITECTURE.md §2.1).

The swap closed five things `openid-client` did that the ported core did not, each with tests:

- **https is enforced** on every endpoint a code, a secret or a key crosses, `localhost` included.
  `BrokerConfig.allowInsecure` now means something; before the swap it was a field with no effect
  left over from `client.allowInsecureRequests`.
- **The discovery document must assert the issuer it was fetched from** (OIDC Discovery 1.0 §4.3),
  with Entra's `{tenantid}` template as the one exception.
- **`iss` on the authorization response is checked** (RFC 9207 §2.4, the mix-up defence). A provider
  advertising `authorization_response_iss_parameter_supported` must send it — oidcraft itself does
  (FR-C14), so `broker.live.test.ts` exercises the required path, not only the optional one.
- **`UpstreamProvider.tokenEndpointAuthMethod`** picks `client_secret_post`, `client_secret_basic` or `none`.
  Before it was whatever `openid-client` defaulted to.
- **FR-F11 is real**: an unreachable upstream, a refusal on the redirect, a wrong `iss` and a failed
  ID token each become a distinct `OAuthError` with the clause that was violated.

`metadata.contract.test.ts` pins the discovery document this OP _writes_ to the type the RP core
_reads_, so renaming an endpoint here is a compile error rather than someone's runtime `undefined`.

## The monorepo: four libraries, one protocol core

Decided 2026-09-18; the three bindings have landed (below). `vue-oidc`, `ngx-oauth` and `react-oauth-oidc` move into this
workspace and their GitHub repositories are archived. The **npm packages keep their names and their
users** — only the repositories are deprecated.

The reason is not tidiness. Read side by side, the three libraries have already converged on the
same module boundaries, independently:

| module                                                    | vue-oidc   | react-oauth-oidc | ngx-oauth    |
| --------------------------------------------------------- | ---------- | ---------------- | ------------ |
| `config` `fetch` `functions` `jwt` `token` `types` `user` | yes        | yes              | yes          |
| storage                                                   | `ref.ts`   | `storage.ts`     | `storage.ts` |
| flows                                                     | `flows.ts` | `flows.ts`       | `oauth.ts`   |
| optional UI `component/`                                  | Vuetify    | yes              | Material     |

That is one design written three times. Every Vue file above the core imports Vue exactly once, and
always the same names — `ref`, `computed`, `watch`, `effectScope`, `inject`. ngx-oauth's library is
47 `inject`, 16 `computed`, 14 `signal`, 12 `effect` and **no RxJS**. React has `store.ts` already.
Three vocabularies for one idea, which is what makes the shared layer possible rather than wishful.

### Target shape

```
packages/
  core/        not published   . protocol   discovery, PKCE, flow, jwt, redirect, types
                               ./client     storage, token lifecycle, refresh, authed fetch
  oidcraft/    oidcraft            the OP
  vue/         vue-oidc            peer: vue
  angular/     ngx-oauth           peer: @angular/core
  react/       react-oauth-oidc    peer: react
apps/
  server/      reference OP, conformance target
  demo-vue/  demo-react/  demo-angular/     the three existing sample apps
```

**A client's directory is its framework; its package name is whatever is already on npm.** The three
published names follow three different conventions — `vue-oidc`, `ngx-oauth`, `react-oauth-oidc` —
because they were named years apart, and they cannot be changed without abandoning their users. A
directory tree that mirrored them would sort badly and say nothing the framework name does not say
better. `bun run --filter` matches package names rather than directories, so nothing in the build
depends on the two agreeing.

The cost is that the folder no longer names the artifact, so each package's README opens with the
name it publishes under, and the table above is the one place the mapping lives.

Two entries because the server must not bundle `localStorage`. `.` exists and is tested; `./client`
is the layer the table above collapses into, written once against a signal interface narrow enough
that `ref`, `signal` and `useSyncExternalStore` each satisfy it. Each binding is then its
`component/`, its `axios/`, and the reactivity glue.

**No published package here depends on another published package here.** That property is what
keeps four publishers out of a version matrix, and `verify-entries.ts` already fails the build if a
workspace-private package leaks into a published bundle. Reversed 2026-11-11: `core` and `client` are
published, as ordinary dependencies rather than peers, which is what avoids the matrix.

### Landed

- **`@oidcraft/client`** — the shared runtime, 137 tests. See the commit for which of the three
  implementations won on each file.
- **`packages/angular` → `ngx-oauth@9`**, on that runtime, and building with tsdown like every other
  package here — the binding is `InjectionToken` factories and `inject()`, so no decorator reaches
  the output and `verify-entries.ts` asserts that. Its instance is now per-injector: v8 kept the
  config, the token and the JWKS in module-level signals, which cannot be answered correctly under
  concurrent SSR.
- **`packages/react` → `react-oauth-oidc@2`**, on that runtime. Almost nothing changed: its binding
  already went through `react-oauth-oidc/core`, now a re-export of the two shared packages.
- **`packages/vue` → `vue-oidc@7`**, on that runtime. Four entries, `./core` kept as a re-export
  because dropping an entry v6 published would break its consumers. The Vue-specific code is two
  functions in `refs.ts`; everything else is shared.

### Decided

- **`ngx-oauth`'s service layer drops `ng-packagr`** — done, see above. The Angular _sample_ still
  needs the Angular CLI, which is a deliberate exception to §1.1's no-bundler rule for apps.

### Closed: `ngx-oauth/component` → `oauthForm()`

**This was assessed wrongly earlier and is worth stating plainly.** "The library has no decorators"
was checked against `projects/ngx-oauth/oauth/` and is true there. But `ngx-oauth/component` is a
**published secondary entry point** with its own `ng-package.json` and a real `@Component` — a
standalone Material login form with an inline template.

That entry cannot ship from tsdown. `erasableSyntaxOnly` forbids the decorator, and relaxing it would
not be enough: an Angular component published without `ngc` reaches consumers as JIT, which breaks
under a production build. Partial compilation is what `ng-packagr` exists to do.

Resolved by not shipping a component at all. `oauthForm()` in the root entry carries what the
Material form was worth — validation, the submit lifecycle, when an error may show, keeping the
username and clearing the password on a rejection — as signals, with the markup left to the host.
`react-oauth-oidc` already shipped the same thing as `useOAuthForm`, so the two bindings now agree.

That keeps `packages/angular` on tsdown and TypeScript 7, inside the workspace and inside `verify`,
with no second island in a published package. The rejected alternatives were a nested `ng-packagr`
install building only `./component`, and moving the whole package out of the workspace; both put a
published entry outside the gate that checks everything else.

`oauthForm()` drives the resource-owner password grant, which OAuth 2.1 removed — so `apps/demo-server`
does not advertise it and `apps/demo-angular` cannot demonstrate it. It is there for the IdPs that
still accept it, which is what v8's component was for too.

The same question will arrive for `vue-oidc/component` if `@vue/compiler-sfc` ever stops resolving
what it currently does — that entry already needed two workarounds to ship at all.

- **Order: vue-oidc, then React, then Angular.** vue-oidc is the reference implementation, React is
  the closest in shape and already on tsdown, and Angular goes last so the signal abstraction has
  been validated against two frameworks before it meets the one with its own toolchain.

### What would make `@oidcraft/core` a published package

Done 2026-11-11, with `@oidcraft/client` — see the move to the `oidcraft` npm org. The reasoning:

It is `private: true` today and that is a deferred decision, not a closed one. What argues for
publishing, once the client libraries are actually here:

- **Propagation.** A fix to the `iss` or nonce handling currently means publishing four packages and
  every user upgrading four. Published, it is one release that anyone on a caret range picks up.
- **Four consumers, not two.** The bundling case was obvious at two.
- Svelte, Solid and vanilla come free rather than on request.

What was _not_ a real argument against it, and should not be reused: the §2.1 version matrix. That
pain is specific to **peer** dependencies, where the consumer reconciles two versions. As an
ordinary dependency there is nothing to reconcile. If it is published, `NFR-D4` needs one word —
zero _third-party_ runtime dependencies beyond `jose` — because the core's own tree is `jose` alone.

### The test DOM, and why it is global

`scripts/test-dom.ts` is preloaded for every test file, because `@testing-library` binds `screen` to
`document.body` when its module is evaluated and one process runs every file — a per-file import
loses that race.

Registering happy-dom globally is safe **only** because that file puts Bun's own globals back
afterwards, and the list is not obvious. `fetch`, because happy-dom's routes through `node:http` and
mis-parses a `Bun.serve` response ("Parse Error: Duplicate Content-Length"). The body types, because
Bun's fetch does not recognise happy-dom's. And `AbortController`/`AbortSignal`, because `jose` gives
its JWKS request a timeout signal and Bun's fetch rejects a foreign one — which surfaces as "invalid
token" on every verification that has to fetch a key set, pointing at everything except the cause.

`crypto` is deliberately **not** in that list: happy-dom leaves `crypto.subtle` alone, and restoring
it would be cargo cult.

### Demo apps

`apps/demo-vue` (was `apps/client`) now resolves `vue-oidc` from the workspace, and `apps/demo-react`
is imported from that library's own sample. Between them the Vue and React bindings are exercised by
something other than their unit tests, which nothing did before.

Both were brought onto this workspace's conventions rather than kept as they arrived: the React app
read `import.meta.env.VITE_*` through a destructure — the exact form §9.2 forbids — and now reads
`OIDCRAFT_PUBLIC_*` as whole `process.env.X` literals from the same root `.env` as everything else,
substituted when its `index.ts` bundles the client (Vite is gone; ARCHITECTURE.md §1). Its `@/` alias
is gone for the same reason. It also stopped carrying
a `clientSecret` into a browser bundle, which the sample did and a public client must not.

`apps/demo-angular` is in too, as a toolchain island outside the bun workspace — ARCHITECTURE.md §8.4
has the why. It is the only app the root `verify` does not cover.

Not carried over from the ngx-oauth sample: its `app.config.ts` had a **live Google OAuth client id
and secret committed**, pointed at `accounts.google.com`. A browser app cannot keep a secret, so it
was replaced with the same public-client-plus-PKCE config the other two demos use. That credential is
still in the ngx-oauth repository's history and is worth rotating.

### The password form, extracted

`createOAuthForm` in `@oidcraft/client`, with each binding wrapping it: `useOAuthForm` in Vue and
React, `oauthForm()` in Angular. Adding Angular's had quietly recreated the duplication this
workspace exists to avoid — two near-identical copies of the same rules, about to become three.

It is **not** a net reduction in lines, and it was predicted to be. The three wrappers are ~75 lines
each rather than the ~25 estimated, because most of each file is the interface restated in that
framework's reactive vocabulary — `Signal`, `ComputedRef`, plain values. The logic in each is about
fifteen lines. What the extraction actually buys is that the _rules_ exist once and are tested once:
when a field may show an error, what survives a rejected attempt, when a dismissed error comes back.

`vue-oidc/component` lost a fourth copy of those rules along the way — it had been validating through
Vuetify's `VForm`, which meant its behaviour could differ from the other two and did (it never
cleared the password after a rejection, and tracked its own error-dismissed flag). It is 32 lines
shorter and now renders what the composable decides.

Vue's shape is flat where the others nest, because Vue unwraps a ref in a template only at the top
level; a nested `form.username.value` would render the ref rather than the string.

### The form, split by purity

The rules moved again, and this time to the right place. `@oidcraft/core` holds what is pure —
`oauthFieldError`, `oauthFieldErrors`, `oauthFormView` and the view types — and `@oidcraft/client`
keeps only the stateful controller. The split is not by consumer but by whether a thing needs a
browser.

That is what let the OP's own login screen join in. It had been the worst-validated form in the
repository: `routes.ts` checked only that a username was non-empty, never read the password at all,
and on failure re-rendered a blank screen with no message. It now validates with the same function
the bindings do, keeps what was typed, and says which field is wrong. `oidcraft/interaction`
re-exports the rules so a host replacing the reference screens validates the same things — pure, so
no UI peer reaches that entry (§8.1), and no HTML reaches the core (FR-I1).

The three bindings then collapsed from 74–82 lines each to 43–53. They had been restating the view
property by property in each framework's primitive, which is most of what a "thin wrapper" was
costing; one reactive `view` plus the controller's actions says the same thing. Vue keeps two
writable refs beside it, because `v-model` needs somewhere to write and Vue unwraps a ref in a
template only at the top level.

### Still open on the Vue move

- **`@vue/compiler-sfc` cannot resolve an imported type under Bun** ("No fs option provided to
  compileScript in non-Node environment"), so the login component's props are written out literally
  in the SFC and pinned to the protocol by two assignments in `component/props.ts`. Not a version
  problem: `unplugin-vue` 8.0.0 is the latest there is, and it fails the same way.
- **The declaration build cannot use the Vue language plugin**, because `rolldown-plugin-dts` refuses
  TypeScript 7 for SFCs. The entry is typed through an ambient `*.vue` shim and a cast instead, which
  is why `component/index.ts` casts through `unknown` — `vue-tsgo` and the dts build genuinely see
  that module differently.
