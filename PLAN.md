# Plan

What is left, in order. `REQUIREMENTS.md` says what it must do, `ARCHITECTURE.md` how.
This file is working state: tick items off and add notes as work lands. Git history holds what
was done.

## Status

**Implemented, as of 2026-11-14**, with 1408 passing tests (235 more skip without Postgres and
Redis) and `bun run verify` as the gate: every functional requirement in `REQUIREMENTS.md`.
`metadata.test.ts` exercises every advertised discovery value rather than reading it. Published as
`@oidcraft/*` — `core` 0.4.0, `client` 0.3.0, the provider 0.4.0, `adapter` and the four storage
adapters 0.2.0, `vue` 9.0.0, `react` 4.0.0, `angular` 11.0.0 — with the docs site at
https://fl0r14n.github.io/oidcraft/. `main` carries the next release (below).

**Provider 0.3.0 and earlier are not to be put in front of real identities**: they ship a session
takeover through `sid` and the other security faults fixed in 0.4.0.

The authorization code grant with mandatory PKCE, interaction suspend/resume, token issuance with
rotation and replay revocation, UserInfo, revocation, introspection, logout in both directions,
DPoP with nonces, PAR, JAR by value, the `claims` parameter, dynamic client registration with RFC
7592 management, the device grant, CIBA in poll and ping, token exchange, RAR, step-up, pairwise
subjects, identity brokering with home-realm discovery chosen by the provider, five storage adapters
(memory, Drizzle, Kysely, TypeORM, Redis) passing one conformance suite, the SQL ones on SQLite,
Postgres, MySQL and MariaDB, four runtime context
providers, local accounts with passwords, passkeys and TOTP, a management API and an admin UI.

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
- **Editing upstream providers from the admin UI** — an issuer and client credentials are deployment
  configuration, not runtime state. The admin shows what is configured.
- **CIBA push mode**, **OpenID Federation 1.0** trust chains (`G-1`, unless a deployment needs it),
  and **upstream SAML** in-tree (`G-4`).
- **A stateless DPoP nonce** — a nonce demand is a storage write a public client can trigger, but
  every proof already costs one for its `jti`, nonce rows live five minutes and are pruned, and a
  stateless nonce would put a new secret in the configuration of a feature off by default.
- **Passkey attestation**, for an enterprise that admits only its own authenticators. Verifying one
  means decoding the CBOR `attestationObject` and validating an X.509 chain, with no dependency but
  `jose` (FR-I8, NFR-D4); an AAGUID allowlist without it checks only what the authenticator says of
  itself. A host that needs attestation brings its own `AccountStore`.
- **Renaming the demo's `/federation/callback`** — it is the redirect URI registered with Google
  (`.env.example`), and renaming a URL people have registered breaks their sign-in for a word.

## Next: the release on `main`

Versions are set in each `package.json`. Publish in this order, each from a GitHub release tagged
`<name>@<version>` (ARCHITECTURE.md §11), waiting for one to reach npm before the next that names it:

1. `@oidcraft/core@0.5.0` — a callback answer without an `access_token` fails a new `token` check;
   `CallbackCheck` gains `'token'`; `authorize` returns `undefined` when nothing answered.
2. `@oidcraft/client@0.4.0` — a sign-in's handoff is keyed by its `state`, out of the shared token,
   finishable in any tab; a failed or stray callback never ends a live session; the bearer goes
   only to allowed origins, `//host` URLs included; redirects are classified by parameter name; an ID
   token that does not verify is no profile, and discovery runs before it is checked; a refresh
   answered late or after a rekey is kept; bindings see a token lapse.
3. `@oidcraft/adapter@0.3.0` — `Credential.passwordHash` is optional, for an account with passkeys alone; the `revoked_family` artifact kind; `fromKv`'s identity key changed,
   so links a Redis store made before it are not found; `AccountStore.claims` documents its third
   argument; `Client.defaultAcrValues`; the conformance suite checks prune, grant expiry and replacing upserts;
   `PasskeyStore`, which `CredentialsAdapter` now requires, the `passkey_challenge` kind, and the
   `passkeys` conformance checks (FR-I8).
4. `@oidcraft/provider@0.5.0` — the review's security and correctness fixes; the `claims` parameter
   (FR-C22), whose consent answers must repeat `view.claims` in `consent.claims`; `onAudit` hears
   `token.replay` and `client.authentication_failed`; a body that is not form-encoded is a 415; a
   throwing logout or registration audit hook goes to `onError`; under a provider-wide FAPI profile
   dynamic registration names the profile's algorithm instead of failing on DCR's RS256 default;
   a client's `default_acr_values` and the configured `acrValues`, advertised (FR-C23); passkeys in
   `./accounts`, behind its new `origin` option, accounts with no password and their recovery, and
   `regenerateRecoveryCodes` moved out of `totp` (FR-I8).
5. `@oidcraft/drizzle@0.3.0`, `@oidcraft/kysely@0.3.0`, `@oidcraft/redis@0.3.0` — peer on `adapter`
   ^0.3.0; the SQL ones enforce `Grant.expiresAt` and prune by expiry at the delete, and store passkeys,
   with migration `0006_passkeys`; `0002_credentials` makes `password_hash` nullable, edited in place. Drizzle and Kysely gain MySQL and MariaDB, one dialect over
   `MYSQL_MIGRATIONS` (`mysqlTables()` for Drizzle, `MysqlDialect` for Kysely).
6. `@oidcraft/typeorm@0.3.0` — the same, and `OIDCRAFT_ENTITIES` becomes `OIDCRAFT_SQLITE_ENTITIES`,
   `OIDCRAFT_POSTGRES_ENTITIES` and, for a `mysql` or `mariadb` `DataSource`, `OIDCRAFT_MYSQL_ENTITIES`.
7. `@oidcraft/vue@10.0.0`, `@oidcraft/react@5.0.0`, `@oidcraft/angular@12.0.0` — majors for what
   `core` and `client` changed underneath them; every binding shows and dismisses an error that came
   without a description.

## Passkeys

FR-I8 is in (2026-11-14), accounts with no password included. A realm on its own subdomain has its
own passkeys, as the relying-party ID is the issuer's host.

**Changing an existing database.** `0002_credentials` was edited in place to make `password_hash`
nullable, rather than adding a migration. A database migrated before that keeps `not null`, and a
passwordless sign-up fails on it: the demo's `apps/demo-server/data` must be deleted, and any other
database altered by hand (`alter column password_hash drop not null` on Postgres, `modify
password_hash text null` on MySQL, a table rebuild on SQLite).

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
declaration build here, not only Vue's. `tsdown` is pinned to ^0.23.7 so a lockfile refresh cannot
bring that in. Move to 7.1 when it is stable, before taking `rolldown-plugin-dts` 0.31; 7.1 is also
what the plugin names for custom languages, so the Vue shim above is worth retrying then.

**Bun, checked 2026-11-13.** Nothing tracks exposing the client certificate to a `Bun.serve` handler:
no issue, no PR. The only movement is on `node:https`: oven-sh/bun#16834 (its `req.socket` is not a
`TLSSocket`) has a fix open, oven-sh/bun#37255, which adds `getPeerCertificate()` to it — still open
and unmerged, last touched 2026-11-06. If it lands, mTLS works on Bun through `./runtimes/node`'s
`toNodeHandler` on a `node:https` server, not through `Bun.serve`, and G-8's re-verification is the
first thing to repeat.

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
