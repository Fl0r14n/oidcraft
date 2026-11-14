# Architecture

How oidcraft is built. `REQUIREMENTS.md` says what it must do; every section here cites the
`FR-*`/`NFR-*` ids it satisfies, and those ids are the contract between the two files.

## 1. Stack

| Choice               | Version    | Why                                                                                                                                                      |
| -------------------- | ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Bun**              | ≥ 1.4.4    | Workspaces, test runner, bundler and HTTP server in one tool. The _development_ runtime; the published packages target no runtime in particular (FR-R1). |
| **TypeScript**       | 7.0.x      | `bun check` for `.ts`, `vue-tsgo` for packages with SFCs; `typescript` stays for tsdown's declaration emit.                                              |
| **Tailwind**         | 4.3.x      | Styling for both apps, via `bun-plugin-tailwind`. No other CSS pipeline.                                                                                 |
| **@vuetify/v0**      | 1.3.x      | Headless Vue primitives, in the **admin surface only** (§8.1). Vue 3.5 is its only dependency.                                                           |
| **Biome**            | 2.6.x      | Lint and format. `biome.json` settles formatting; it is not a matter of preference.                                                                      |
| **jose**             | ^6         | The only third-party runtime dependency. WebCrypto-backed, runtime-agnostic (NFR-D4).                                                                    |
| **@oidcraft/core**   | workspace  | The protocol, shared by the provider and every client binding (§2.1). Published; a dependency of each.                                                   |
| **@oidcraft/client** | workspace  | The stateful client runtime, shared by the client bindings only (§2.1). Published; never the server's.                                                   |
| **tsdown**           | 0.23.x     | Library build: the provider's eight ESM entries and every package's, with `.d.mts` types (§2.2).                                                         |
| **Drizzle / Kysely** | 1.0 / 0.29 | First-party adapters (FR-A4). Optional peers, never bundled (§2.2).                                                                                      |
| **TypeORM**          | 1.1        | First-party adapter (FR-A6) over the host's `DataSource`, with `EntitySchema`s rather than decorators. Optional peer, never bundled.                     |

### 1.1 No bundler, no build step — with one measured exception

`bun index.html` **is** the client: Bun's dev server bundles the Vue SFCs, compiles Tailwind, inlines
`OIDCRAFT_PUBLIC_*` and serves the page with HMR. The server app runs from source. No `Bun.build`
script, no `dist/`, nothing to keep in sync between a dev path and a build path.

`apps/demo-react` is the exception, because it demonstrates SSR — `useSyncExternalStore`'s server
snapshot is what a relying-party binding gets wrong — and Bun's HTML imports have nowhere to put
server-rendered markup. Its `index.ts` is a `Bun.serve` host that imports `entry-server.tsx` and
bundles `entry-client.tsx` with `Bun.build` at startup; still no `dist/`. The price is Fast Refresh:
`bun --watch` restarts the host and the page reloads. Its `Bun.build` substitutes `OIDCRAFT_PUBLIC_*`
as whole `process.env.X` literals, every name defined even when unset, so §9.1 holds there too.

Two sharp edges:

- **Plugins come from the bunfig next to the served entrypoint**, via `[serve.static]`, not the
  root one (§9.3). Without it a `.vue` import is served as a path string and the page is blank.
- **No `@/` path alias in the apps.** `paths` resolve under `bun build` but not under the dev
  server, which fails with `ENOENT … /src/@/App.vue`. App-internal imports are relative.

The docs site is the one app with a real build, and the one with Vite (§8.5).

### 1.2 TypeScript 7 and Vue

`vue-tsc` does not run on TypeScript 7, so a package with `.vue` files type-checks with `vue-tsgo`.
Every `typecheck` is `bun check`, which runs a package's own `check` script when it has one — and
that is where `vue-tsgo` lives, because `bun check` skips `.vue` files. Not `tsgo`, the older
`@typescript/native-preview` binary. The `typescript` package stays for tsdown's declaration emit.
The Angular demo's `check` is TypeScript 6's `tsc`, which its compiler needs (§8.4).

## 2. Workspace

```
packages/core/              @oidcraft/core      the protocol (§2.1)
packages/client/            @oidcraft/client    the client runtime, the bindings only
packages/ui/                @oidcraft/ui        private, consumed from source by apps/demo-server (§8.1)
packages/vue/               @oidcraft/vue
packages/react/             @oidcraft/react
packages/angular/           @oidcraft/angular
packages/adapter/           @oidcraft/adapter   the storage contract (§4)
  src/index.ts              .                   Adapter, its stores and records, fromKv, the key stores
  src/memory/               ./memory            tests and development only
  src/conformance/          ./conformance       the storage guarantees as checks, for any test runner
packages/sql/               @oidcraft/sql       private: the schema the SQL adapters share, compiled into each (§4.2)
  src/sqlite.ts             ./sqlite            SQLITE_MIGRATIONS
  src/postgres.ts           ./postgres          POSTGRES_MIGRATIONS
  src/mysql.ts              ./mysql             MYSQL_MIGRATIONS, for MySQL and MariaDB alike
  testing/                  ./testing           Postgres schemas and MySQL databases for the adapters' tests
packages/drizzle/           @oidcraft/drizzle   Postgres, SQLite, MySQL/MariaDB
packages/kysely/            @oidcraft/kysely    Postgres, SQLite, MySQL/MariaDB
packages/typeorm/           @oidcraft/typeorm   a TypeORM DataSource; Postgres, SQLite, MySQL/MariaDB
packages/redis/             @oidcraft/redis     any Redis client, through one command function
packages/provider/          @oidcraft/provider  the provider, eight entries
  src/index.ts              .                   the OP. fetch in, fetch out, no I/O
  src/broker/               ./broker            the relying-party leg — upstream brokering
  src/interaction/          ./interaction       login/consent policy types
  src/accounts/             ./accounts          local accounts: passwords, passkeys, TOTP, recovery codes, reset (FR-I7, FR-I8)
  src/runtimes/node/        ./runtimes/node     node:http bridge + request context
  src/runtimes/bun/         ./runtimes/bun      request context for Bun.serve
  src/runtimes/deno/        ./runtimes/deno     request context for Deno.serve
  src/runtimes/workerd/     ./runtimes/workerd  request context for Cloudflare Workers
apps/
  demo-server               the reference OP: mounts the core, the login screens and the admin UI
  demo-vue                  demo relying party: Vue 3 + @oidcraft/vue
  demo-react                demo relying party: React 19 + @oidcraft/react, with SSR
  demo-angular              demo relying party: Angular 22 + @oidcraft/angular. Outside the workspace (§8.4)
  docs                      the documentation site: VitePress over the root docs and READMEs (§8.5)
```

Inside the root entry, code is grouped by feature, not by HTTP route: a folder holds a flow's
endpoint, the grant the token endpoint dispatches to, and the host-facing functions together.

```
src/authorize/    authorization, PAR, request objects, PKCE, the claims parameter, interactions,
                  consent, and the two flows that start without a redirect: device and CIBA
src/token/        the token endpoint as a dispatcher, the code and refresh grants, client
                  credentials, token exchange, and minting: ID token, JWT access token, subjects
src/binding/      sender-constrained tokens — DPoP (RFC 9449) and mTLS (RFC 8705)
src/clients/      client authentication, JWT client assertions, dynamic registration
src/session/      the OP session cookie, RP-initiated logout, logout notifications
src/resource/     what a resource server calls: UserInfo, introspection, revocation, step-up
src/keys/         the key store and the JWKS endpoint
src/upstreams/    upstream selection (FR-F4) and the linked identities — the root's side of
                  brokering; the relying-party leg is the `./broker` entry
```

Each folder's `management.ts` holds its operator functions (FR-M1); the root `management.ts` only
assembles them into `provider.management`. None of these folders has an `index.ts`:
`exports.test.ts` treats a directory with one as a published entry. Tests sit beside the module
they test, over one harness, `src/test-flow.ts`.

### 2.1 Eleven published packages, one scope

Everything published is under the `@oidcraft` npm org, and each package is named for its directory:

| package              | directory           | what                                                                                     |
| -------------------- | ------------------- | ---------------------------------------------------------------------------------------- |
| `@oidcraft/core`     | `packages/core`     | the protocol: discovery, PKCE, the authorization round trip, ID token verification       |
| `@oidcraft/client`   | `packages/client`   | the stateful client on top: storage, token lifecycle, refresh, authorized fetch, profile |
| `@oidcraft/adapter`  | `packages/adapter`  | the storage contract: stores, records, `fromKv`, key stores, memory, conformance         |
| `@oidcraft/provider` | `packages/provider` | the OpenID Provider, eight subpath entries                                               |
| `@oidcraft/drizzle`  | `packages/drizzle`  | the Drizzle adapter                                                                      |
| `@oidcraft/kysely`   | `packages/kysely`   | the Kysely adapter                                                                       |
| `@oidcraft/typeorm`  | `packages/typeorm`  | the TypeORM adapter                                                                      |
| `@oidcraft/redis`    | `packages/redis`    | the Redis adapter                                                                        |
| `@oidcraft/vue`      | `packages/vue`      | Vue binding over `@oidcraft/client`                                                      |
| `@oidcraft/react`    | `packages/react`    | React binding over `@oidcraft/client`                                                    |
| `@oidcraft/angular`  | `packages/angular`  | Angular binding over `@oidcraft/client`                                                  |

`@oidcraft/ui` and `@oidcraft/sql` are the two private packages, consumed from source: the screens by
`apps/demo-server` (§8.1), the SQL schema by the SQL adapters. The three bindings continue packages
published under older names — `vue-oidc`, `react-oauth-oidc`, `ngx-oauth` — and their version
numbers continue those.

**The adapters are packages, on a contract package, never on the provider.** The provider and an
adapter do not depend on each other; the host installs both and hands one to the other:

```
@oidcraft/adapter      the contract: Adapter and the store types, the records they hold, fromKv,
                       the key stores, the memory adapter, the conformance suite; depends on
                       @oidcraft/core for the client's identity, types only
@oidcraft/provider     depends on @oidcraft/adapter, and re-exports its types
@oidcraft/drizzle      peer on @oidcraft/adapter and on drizzle-orm
@oidcraft/kysely       peer on @oidcraft/adapter and on kysely
@oidcraft/typeorm      peer on @oidcraft/adapter and on typeorm
@oidcraft/redis        peer on @oidcraft/adapter
```

So a provider release ships without an adapter release, and a contract mismatch is an install
warning rather than a type error in the host. An adapter peering on the provider would instead be a
version matrix per adapter.

`@oidcraft/adapter` carries behaviour, not only types: `fromKv`, the memory adapter, the suite, the
key stores (`staticKeyStore`, `generateKey`, `generatedKeyStore`) and the `ConfigurationError` they
throw, which the provider re-exports. What the protocol does with keys — choosing the signing key,
the JWKS body — stays in the provider.

A client's identity is declared once, in `@oidcraft/core`: `ClientCredentials` and
`ClientAuthMethod`, the RFC 7591 registry, with `TokenAuthMethod` the subset a client can send.
Core's client configs, the broker's `UpstreamProvider` and the adapter's `Client` each build on them,
all naming the method `tokenEndpointAuthMethod`. Scope is the exception: core keeps `scope` as the
string the bindings' users pass, the provider keeps `scopes` as the list it stores and compares.

The SQL schema is not contract — only the three SQL adapters read it — so it is `@oidcraft/sql`,
private, and each compiles in its own copy, as it does the row mapping Kysely and TypeORM share
(`@oidcraft/sql/rows`: JSON as text, times as epoch milliseconds). It has a build of its own so they
bundle its `dist`, not its sources, whose declaration build would write stray `.d.ts` files beside
them; importing it by name fails `verify-entries.ts`, since it is only a `devDependency`. One package
rather than one per dialect, because both lists must keep the same ids (§4.2).

The runtimes stay provider subpaths: each is a few dozen lines and needs the provider's own types.
The cost of the split is a release order and, per new package, a manual first publish (§11).

**Core and client are split by consumer.** `@oidcraft/core` serves `@oidcraft/provider/broker`,
because brokering _is_ being a relying party at the upstream (§5), and the framework bindings,
whose users have no OP at all. Only the bindings want `@oidcraft/client`; a server reaching
`localStorage` would be a bug, so `verify-entries.ts` fails the build of any server entry importing
it (§2.2).

**They are dependencies, not compiled in.** One release of `@oidcraft/core` fixes the provider and
all three bindings; an application using a binding and the broker installs one copy of the protocol;
and a framework without a binding builds on `@oidcraft/client` directly. The price is that their
exports are semver contracts, released before what names them. NFR-D4 stays true: `dist/broker.mjs`
imports `@oidcraft/provider`, `@oidcraft/adapter`, `@oidcraft/core` and `jose`, and nothing else.
`@oidcraft/client` keeps `@oidcraft/core` external too: a second copy of the protocol types in its
declarations makes a binding's dts emit fail with "cannot be named". The provider uses core's
`sha256`, `randomString` and `constantTimeEquals` rather than its own; encoding is `jose`'s
`base64url`.

### 2.2 Entry invariants

Each optional peer is confined to the one entry that owns it, which is what keeps it optional. Only
`verify-entries.ts` enforces this, and every way of breaking it fails silently otherwise: a leaked
peer is a resolution error in a consumer who never installed it, and a core type inlined into an
entry compiles fine while shipping a second copy that drifts. In the provider the same holds for the
storage libraries, which belong to the adapter packages.

Every package a bundle imports must be declared in its `package.json`: a workspace package imported
but undeclared resolves here and nowhere else. And the shared ones must stay imported —
`@oidcraft/core` by `./broker` and by each binding's `./core`, `@oidcraft/client` by the React and
Angular `./core`, `@oidcraft/adapter` by the provider and by every adapter — because a copy compiled
in is one a release of it no longer fixes.

Each package's `verify-entries.ts` runs after its `build`. The provider's asserts, per entry: no
storage library, in either the JS or the `.d.mts`; no undeclared import; no `@oidcraft/client`; no
`node:` builtin outside the `./runtimes/node` entry (FR-R1); no redeclared core type; and — once an
entry has runtime code — that it imports the root by package name rather than inlining a second
copy of the core. `@oidcraft/adapter`'s and each adapter's assert no undeclared import, no runtime
builtin or global, `@oidcraft/adapter` and the database library imported by name, and a suite that
imports no test runner. Entries that are still types-only compile to `export {};`, so their runtime
checks are reported as pending rather than passing quietly.

## 3. The core

### 3.1 Request pipeline

The root entry exposes one function of `(Request, RequestContext) => Promise<Response>`. It is the
whole surface. Of the context it reads the client certificate; the client IP is the host's, for the
limits it applies (NFR-S12).

> **workerd**, the engine behind Cloudflare Workers, is named throughout as the strictest non-Node
> target: no filesystem, no `node:net`, no process outliving a request, no timers between requests.
> FR-R1, FR-R2, FR-A1 and NFR-P3 are effectively its constraints, shared by Deno Deploy, Vercel Edge,
> Netlify Edge and Fastly Compute.

**Only Node needs an HTTP bridge.** Bun, Deno and workerd hand over a `Request` and take a
`Response`, so the handler mounts into their servers directly.

**Every runtime needs a context provider.** Nothing in `RequestContext` is carried by `Request`,
and each runtime exposes it differently: `server.requestIP(request)` on Bun, `info.remoteAddr` on
Deno, `req.socket` on Node, `request.cf` plus `CF-Connecting-IP` on workerd. Hence one small entry
per runtime under `@oidcraft/provider/runtimes/*`, each touching only its own globals and holding no
protocol logic (FR-R3); `verify-entries.ts` fails the build if `node:`, `Bun.` or `Deno.` appears
outside the entry that owns it (§2.2).

**mTLS client authentication is unavailable on Bun.** `Bun.serve` can request a client certificate
but exposes no way to read it, so `tls_client_auth` and certificate-bound tokens are refused at
construction there rather than advertised (`G-8`, FR-R5).

```
Request
  → route            static table over the configured endpoint paths
  → authenticate     client authentication (FR-C4), or none for public endpoints
  → validate         parameters, then the request object / PAR payload (FR-C12)
  → policy           can this proceed, or is an interaction required? (FR-I1)
  → issue            mint artifacts, persist through the Adapter
  → respond          Response, including the OAuth error shape on every failure path
```

`RequestContext` carries what the core cannot learn from the `Request` on its own authority: the
verified client certificate for mTLS and the client IP (FR-R4). The issuer is not in it: it is
configuration, never derived from a request (NFR-S6).

Where a request ends, an unexpected failure goes to `onError` and is answered `server_error`
(NFR-D5), and a refusal that answers an attack carries an audit event to `onAudit` (FR-M3). Host
hooks called after something already happened — logout delivery, an audit after a registration —
are guarded the same way: a failure is reported, never answered (`src/hooks.ts`).

**CORS is decided by the registration, not by configuration.** Discovery and the key set are
readable from any origin. A preflight on the token, UserInfo, revocation or introspection endpoint
is answered for any origin, since it only permits what a form post from there could already send;
the real response is readable only from the origin of one of the calling client's registered
redirect URIs — the client the request authenticates as, or at UserInfo the one its access token was
issued to. No cookie is ever sent cross-origin.

### 3.2 What the core does not do

No HTML beyond the `form_post` response page. Two cookies, both host-only, `HttpOnly`,
`SameSite=Lax`, and `Secure` on an https issuer: the session cookie, `oidcraft.sid`, which carries a
secret whose hash is the session's id and `sid` (NFR-S11), and `oidcraft.browser` (`__Host-` prefixed
on https), which binds an interaction to the browser it was started in (FR-I2). No timers, no
background sweeps, no connection pool, no process-level cache that survives a request (FR-A1,
NFR-P3), so two processes behind a load balancer behave as one. No cap on a request body's size:
that is the host's, in front of the provider (NFR-S12).

### 3.3 The FAPI 2.0 profile

`src/profile/fapi.ts` is the whole of FR-C21: the algorithms and authentication methods it allows,
what a provider and a client must be, and `underFapi(config, client)`, which every enforcement
point asks. `profile: 'fapi2'` sets it for the provider or for one client; there is no other way in.
It is checked at construction for a provider-wide profile (NFR-D2), at registration and in the
management API for a client, and on every request, since a client can reach storage by neither.

Signing keys are only readable asynchronously, so a key set without a PS256, ES256 or EdDSA key is
refused at its first signature rather than at construction. A provider-wide profile narrows
discovery; a per-client one cannot, since discovery speaks for every client. Its refresh tokens are
the one place rotation is skipped (FR-T3).

## 4. The adapter layer

`packages/adapter/src/adapter.ts` is the contract, published as `@oidcraft/adapter` (§2.1). Storage
is **a set of narrow capability stores**, not one table keyed by a model-name string:

| Store                 | Holds                                                                                                         |
| --------------------- | ------------------------------------------------------------------------------------------------------------- |
| `ClientStore`         | Registered clients. `create`/`update`/`destroy` are optional — omitting them disables DCR at runtime (FR-C9). |
| `ArtifactStore`       | Codes, access and refresh tokens, device codes, PAR and CIBA requests. Revoked by grant, family and client.   |
| `SessionStore`        | The end-user's authenticated session at the OP, including its upstream provenance (FR-F6).                    |
| `GrantStore`          | Durable consent to scopes and named claims. Survives token revocation (FR-I4), not its client (FR-T7).        |
| `AccountStore`        | The host's users. Claims are resolved per request, never cached at login (FR-C5).                             |
| `KeyStore`            | Signing keys, newest first (FR-C10).                                                                          |
| `ReplayGuard`         | One-shot values (NFR-S5).                                                                                     |
| `LinkedIdentityStore` | `(provider, subject) → account` links. Optional; only brokering deployments need it.                          |

The record-holding stores — clients, artifacts, sessions, grants, identities — share one shape,
`EntityStore<T, Id>`: `find`, `upsert` and `destroy`, with a composite key passed as arguments
(`artifacts.find(kind, id)`). Each adds only the lookups the protocol needs indexed. `AccountStore`,
`KeyStore` and `ReplayGuard` keep their own shapes: the host's users read-only, signing keys newest
first, and one atomic claim.

`Adapter` is what a custom adapter implements: the seven stores every provider reads, with
`identities`, `credentials`, `passkeys` and `realms` optional. An entry point that needs one says so in its type
— `createBroker` and `linkIdentity` take a `BrokeringAdapter`, `createAccounts` a
`CredentialsAdapter` (`credentials` and `passkeys`), a realm control plane a `RealmsAdapter` — and every first-party adapter
returns `FullAdapter`, which satisfies each. `createProvider` takes a plain `Adapter` and refuses
`upstreams` without the brokering stores at construction (NFR-D2).

**A consent is a merge, never a write over another (FR-I4).** `grants.merge` adds scopes and claims
to the one grant of an account and client, or starts it, and treats an expired grant as gone, so its
tokens are not revived under a new consent. The SQL adapters compare-and-swap on the stored columns;
`fromKv` serializes consents to one pair behind a lock taken with its atomic `insert`.

**A revocation is not undone by a request already past its checks (FR-T3, FR-T7).** Revoking a
family writes a `revoked_family` artifact before it sweeps the family's rows, and revoking a grant
destroys the `Grant` before it sweeps its tokens. Every write into a family reads both after writing
and sweeps again if either says revoked: either the writer sees the mark, or the sweep, which follows
the mark, sees the write. No store needs a transaction for it.

**No bearer credential reaches an adapter as itself (NFR-S11).** `createProvider` wraps the
`ArtifactStore` it is given (`src/artifacts.ts`), so each bearer artifact is stored under the
SHA-256 of its value and a copy of the database redeems nothing — one wrapper in the provider rather
than a rule for five adapters to remember. Unsalted, because each value is 288 random bits. A record
found by its value comes back carrying that value; one found another way — a device request by its
user code — carries the stored id and is never written back, which is why the answer to a device
request is a record of its own. A registration access token is hashed the same way on the client
record. A JWT access token's `jti` is what its record is stored under a hash of: the JWT finds the
record once its signature verifies, the `jti` presented bare finds nothing (FR-T2).

A client secret is the one bearer value a host writes itself, so it is a field rather than a
wrapper: `Client.clientSecretHash`, made by `hashClientSecret`, is what `client_secret_basic` and
`client_secret_post` compare against, and `clientSecret` is only ever `client_secret_jwt`'s HMAC key.
Registration and the management API return a generated secret once; a hashed one can only be rotated
(`management.clients.rotateSecret`). A host-chosen secret is hashed as given, unsalted, so it is only
as strong as the host made it.

The Drizzle adapter's tests assert with `explain query plan` that revoking by grant and looking up a
user code hit an index rather than scanning — what the blob shape below cannot do.

### 4.1 Why not `oidc-provider`'s shape

`oidc-provider`'s adapter is a single class instantiated per model name, with an untyped
`AdapterPayload` for every method. Every implementation of it ends up as one table of
`(kind, id, payload jsonb)`, so the queries the protocol needs (revoke by grant, find by user code,
expire a range) run against JSON extraction instead of an index, and the payload is `any` at every
call site.

Splitting by capability makes each payload a real type, lets a relational adapter use real columns
and indexes (FR-A5), and lets a deployment implement only what it uses. `KvStore` (FR-A3) keeps the
simple case simple: an `EntityStore` of `{ key, value, ttl }` entries plus `scan` and `insert`, from
which `fromKv` derives the rest. `insert` carries the only hard requirement — it must be atomic —
because every single-use rule is that one write. Redis `SET NX`, a Durable Object or a single-process
`Map` qualify; Workers KV does not.

`consume` and `claim` are atomic in every adapter for the same reason: each returns whether _this_
caller won, and the protocol trusts that answer rather than an earlier read. The SQL adapters use a
conditional `UPDATE … WHERE consumed_at IS NULL` and an upsert that takes over only a lapsed row,
both with `RETURNING`; an artifact upsert never writes `consumed_at`, so a stale read written back
cannot revive a consumed code. The shared conformance suite races eight callers against each.

### 4.2 Schema ownership

An adapter ships migrations the host runs. The library never creates or alters a table at boot: one
that migrates on import migrates during a rolling deploy, from several processes at once.

`SQLITE_MIGRATIONS`, `POSTGRES_MIGRATIONS` and `MYSQL_MIGRATIONS` come from the private
`@oidcraft/sql` (§2.1) and are exported by `@oidcraft/drizzle`, `@oidcraft/kysely` and
`@oidcraft/typeorm`, which query the same tables: ordered `{ id, statements }` records with the same
ids in all three, data rather than a runner, so the host applies them with its own tool. TypeORM gets
them as migration classes too. Every adapter's tests build their database from them, so the shipped
schema is the tested one — Postgres, MySQL 8.4 and MariaDB 11 in CI's service containers and through
`compose.yml` locally; without `POSTGRES_URL`, `MYSQL_URL` or `MARIADB_URL` those suites skip, as
Redis's do. `apps/demo-server` applies them at boot, safe only because it is one process.

The Postgres tables keep milliseconds in `bigint` and JSON in `text`, so every adapter reads and
writes what it does on SQLite; `pg` and Bun.sql return `bigint` as a string, so the adapters convert
with `Number()`. Drizzle fixes a table's schema when the table is defined, so its Postgres tables come
from `postgresTables(schema?)`, and its MySQL ones from `mysqlTables(database?)`. Table names are
unqualified everywhere else, so a host picks the schema with the search path or Kysely's `withSchema`.

**MySQL and MariaDB are one dialect**, written to what both accept and held to both servers by the
same suite (FR-A4). That rules out `RETURNING` (MariaDB's only) and both servers' names for an
upsert's new values: MySQL's row alias, which MariaDB rejects, and `VALUES(col)`, which MySQL
deprecates. An upsert binds its values again, and `@oidcraft/typeorm` writes that statement itself,
since TypeORM's own is `VALUES(col)`. No row count is read where it could change meaning: `mysql2`
counts matched rows as affected by default and a host may turn that off, so insert-if-absent catches
duplicate-key error 1062, every conditional `UPDATE` excludes a row it would not change, and a merge
that adds nothing returns before writing. `ON DUPLICATE KEY UPDATE` answers a clash on any unique
key, so the one table with two, `oidc_credentials`, is upserted by key instead: a username taken by
another account fails rather than rewriting that account's row. Every table is `utf8mb4_bin`, since
every id compares case-sensitively and MySQL's default collations do not. Keys are sized `varchar`,
each index under InnoDB's 3072 bytes; a passkey's credential id, up to 1364 characters, is `ascii`
to fit, and the replay guard stores a SHA-256 of each value, since a client chooses its `jti`'s
length. A prune is `DELETE … ORDER BY expires_at LIMIT n`, as MySQL refuses a `LIMIT` in an `IN`
subquery.

## 5. Identity brokering

### 5.1 Two things named federation

**Identity brokering** is what oidcraft implements (FR-F*): it is the OP its clients see, and a
relying party at one or more upstream OPs. Downstream clients never learn an upstream exists. The
relying-party leg is `@oidcraft/core` — the code a browser application would use against this OP,
pointed the other way (§2.1). **OpenID Federation 1.0** is a different protocol, deferred (`G-1`), and
nothing in the core should assume it away.

### 5.2 The two legs

```
  client ──authorization request──▶ oidcraft ──▶ interaction: which upstream? (FR-F4)
                                       │
                                       ├── @oidcraft/provider/broker is the RP:
                                       │     authorization request ──▶ upstream OP
                                       │     callback ◀── code + state + PKCE verifier
                                       │
                                       ├── claim mapping (FR-F7), account link (FR-F5)
                                       ├── local session records `idp` + upstream session (FR-F6)
                                       │
  client ◀──────code──────────────────┘  the downstream interaction resumes
```

The handoff (`src/broker/types.ts`) carries `state`, `nonce`, the PKCE verifier and **the id of the
downstream interaction it resumes**, which makes this one suspended authorization request rather
than two flows stapled together — and is why the handoff must be single-use, expiring and bound to
the browser that started it (FR-F3).

### 5.3 Why brokering lives in the core, not in the app

Four things reach into the protocol core and cannot be bolted on from outside:

- **Session provenance.** `idp`, `acr`, `amr` and `auth_time` in a brokered ID token are the
  upstream's answers, so `SessionStore` must carry them (FR-F6).
- **Re-authentication.** `prompt=login`, `max_age` and a raised `acr_values` have to force a fresh
  _upstream_ authentication (FR-F9).
- **Logout.** An upstream back-channel logout must end the local sessions it produced, and so this
  OP's back-channel logout to its clients: `SessionStore.findByUpstreamSession` (FR-F8). The other
  direction is a hook: end-session hands a brokered session and its destination to
  `ProviderConfig.upstreamLogout`, and the broker's `logoutUrl` answers with the upstream's
  end-session request, keeping the destination for `completeLogout` and the upstream ID token it kept
  at sign-in as the hint.
- **Home-realm discovery.** Choosing the upstream from `login_hint`, `acr_values` or the client's
  allowed list happens inside the authorization endpoint's policy step (FR-F4).

### 5.4 Pure-proxy mode

With no local credentials, oidcraft is a protocol-normalising proxy: one issuer, one set of client
registrations, one token format, several upstreams behind it. `sub` is then derived from
`(provider, subject)` and stable per account — never the upstream's, which is only unique within
that upstream.

### 5.5 The linking hazard

Matching a brokered identity to a local account by email address is account takeover the moment an
upstream does not verify addresses, or lets a user change one. The default is `(provider, subject)`
and nothing else (FR-F5, NFR-S8). `verified-email` requires `email_verified` from the upstream and is
still a deliberate operator decision; `interactive` — prove control of the existing account, then
link — is the honest answer for a consumer-facing deployment.

### 5.6 Upstream tokens

Off by default and opt-in per provider; then handed to the host only, with the brokered identity.
The library stores none and returns none to a downstream client (FR-F10, NFR-S9). An upstream ID
token is kept only as a logout hint, for a provider that propagates logout (FR-F8).

## 6. Interaction

The authorization endpoint decides what it can and, when it cannot finish, emits an
`InteractionRequest` and redirects (FR-I1). The interaction app — any HTTP app on the issuer's
host — answers with an `InteractionResult`, and the core re-evaluates the original request against
it, free to demand another interaction (FR-I2). The answer comes with the request's `cookie` header,
because an interaction is bound to the browser the redirect set the `oidcraft.browser` cookie in; an
id alone completes nothing.

This is `oidc-provider`'s model: it keeps HTML out of the protocol core and lets a host replace the
screens entirely. oidcraft also ships the screens (FR-I3) and the consent-memory model (FR-I4),
which remembers scopes and claims consented to by name (FR-C22).

### 6.1 Local accounts

`@oidcraft/provider/accounts` (FR-I7) is a set of functions, not a screen or a route: the interaction
app calls `authenticate`, then `verifySecondFactor` when the result says one is enrolled, and only
then completes the interaction. It is composed in after the adapter exists —
`createProvider({ adapter: { ...adapter, accounts: accounts.store } })` — which is why every adapter
takes `accounts` as optional.

It stores through the adapter's `credentials` store and adds no guarantee of its own: a TOTP step and
a recovery code are single-use through `ReplayGuard` (namespaces `totp` and `recovery`), a reset
token through the `password_reset` artifact's atomic `consume`, and a username is unique through
`CredentialStore.create`, atomic in every adapter. Attempts are counted by claiming numbered slots
from `ReplayGuard` (namespace `sign_in`), the one atomic counter every adapter has: an attempt claims
a slot of its address's bucket, or the account's without an address, _before_ the slow verify, so
however many arrive at once no more than the limit are checked; a failure also claims one of the
account-wide bucket's (`G-9`). A second factor has a bucket of its own. The `sign_in_attempts`
artifact holds only each bucket's generation, which a good sign-in renews, and its lock.

**Passkeys (FR-I8)** are WebAuthn with attestation `none`, so the registration's key is the browser's
word, taken from `getPublicKey()` as SubjectPublicKeyInfo: nothing decodes CBOR (NFR-D4), and an
assertion is checked with WebCrypto alone — relying-party ID hash against the issuer's host
(`origin` in `createAccounts`), client data origin, user-present and user-verified flags, the
signature (an ES256 one converted from DER), and a counter that must rise unless both sides keep
none. Each ceremony's challenge is a `passkey_challenge` artifact under its own value, bound to the
interaction, or for a registration to the account, a sign-up's interaction or a reset token's digest,
and taken by the atomic `consume` before any check can fail, so a challenge is spent whether its
ceremony succeeds or not. A sign-up's challenge carries the username, claims and a fresh account id,
so the account and its passkey are written only once the authenticator has answered. `PasskeyStore` is keyed by
credential id, which an assertion names, and its `create` is atomic, so a credential id registered to
one account is refused rather than moved to another. The user handle is an HMAC of the account id
under `secretKey`, stable and naming no one, since an account id may be a username. A passkey is a
second factor only beside TOTP: an account with passkeys and no TOTP still signs in with a password
alone, so losing a passkey never locks a password account out, and a password reset does not need one.

An account made with a passkey has no `passwordHash`. `authenticate` pays the decoy hash for it and
fails, `totp.begin` refuses it, and `passkeys.remove` refuses its last passkey; two removals that race
past that count each re-list after deleting, and one that finds none left puts its passkey back. Its
way back in is a reset token: `recover` spends a recovery code for one, and `reset.issueForAccount`
issues one for an administrator. The token's page adds a passkey through a creation ceremony bound to
the token's digest, spending the token only once the authenticator's answer verifies, or sets a
password, and either ends the account's sessions and revokes its grants' tokens as a reset does (FR-T7).

Hashing is injected, because the fast hashers are runtime globals: `bunPasswordHasher` lives in
`./runtimes/bun` and `nodePasswordHasher` in `./runtimes/node`, both writing PHC argon2id strings the
other verifies. A Deno or workerd host passes its own.

## 7. Administration

The root entry exposes the management surface as functions on the provider, `provider.management`,
over clients, grants, sessions, keys and upstreams (FR-M1); none of it is a route. **The library
never decides who is an administrator** — the host calls these from handlers behind its own
authentication. Writes, replays and failed client authentications emit audit events the host routes
somewhere; the library persists none of them (FR-M3).

### 7.1 Realms

A realm is a provider. `createRealms({ store, realmOf, configure, provision, retire })`, exported
from the root beside `createProvider`, keeps a cache of providers keyed by realm id and builds each
from its record on first use (FR-M4). There is no realm mode in the core: a deployment with one
issuer never calls it.

- **The host owns the URL scheme.** `realmOf` reads a subdomain, a path prefix or a custom domain.
  What it returns is only a selection: ids are DNS labels, and an unknown or disabled realm resolves
  to `undefined` without `configure` running, so a forged `Host` header cannot mint an issuer
  (NFR-S6).
- **Storage is per realm.** `configure` hands each provider its own adapter — a SQLite file, a
  Postgres schema (`postgresTables(realm.id)`, `db.withSchema(realm.id)`, or the search path), a
  MySQL database (`mysqlTables(realm.id)`, `db.withSchema(realm.id)`), a Redis prefix. Each
  adapter's Postgres and MySQL suites check that two schemas share nothing. The
  `oidc_realms` table (migration `0003`) is only the registry, in the control plane's storage; no
  other table gains a realm column (`G-6`).
- **Keys are per realm, and checked.** A key two realms share would let one realm's token verify
  against the other's JWKS. `generatedKeyStore()` keeps one RSA key per process, so building a realm
  whose key ids collide with another's throws instead of serving it.
- **Lifecycle order.** Create inserts the record disabled, runs `provision`, then enables it, so a
  half-built realm is never served and a failed `provision` frees the id. Remove disables first,
  then runs `retire`, then deletes the record.
- **Several processes.** `forget` clears one process's cache. Every process re-reads a cached
  realm's record after `revalidate` seconds (default 30) and rebuilds when anything in it changed —
  the whole record, not `updatedAt`, which a same-millisecond write or a hand edit need not change.
- **The control plane is a plain provider.** The operator signs in through a `createProvider`
  issuer, and the realm management functions sit behind the host's own authorization (FR-M1).

## 8. Apps

### 8.1 `apps/demo-server` — the reference OP

One `Bun.serve` process mounting the core's fetch handler, the reference interaction screens and the
admin UI. It is the deployment the conformance suite runs against (NFR-C1): a reference that is
never executed is a reference that is wrong.

**One component set, rendered two ways.** `packages/ui` (`@oidcraft/ui`) holds the design, the Vue
components and the interaction screens. It is private and has no build: the app imports its source.
`@oidcraft/provider/interaction` ships rules and no markup, so no consumer of the library inherits a
UI dependency (FR-I3).

The components are grouped by atomic-design level, each importing only from the levels below it:
`atoms/` are single elements (`UiButton`, `UiInput`, `UiLink`, `UiAlert`), `molecules/` a few working
as one (`UiField`), `organisms/` a distinct section of an interface (`UiSection`, `UiDataTable`,
`UiDialog`, the passkey forms), `templates/` a page's layout with slots (`UiCard` for the interaction
screens, `UiShell` for the admin and account apps), and `pages/` the interaction screens, a template
filled in. `@oidcraft/ui/components` exports the reusable levels and `createScreens` the pages, so
where a component sits is not part of either API.

**The design is a handful of CSS variables** (`--oc-accent`, `--oc-accent-ink`, `--oc-radius`,
`--oc-font`) that Tailwind's theme reads. `createScreens({ brand, theme, urls })` takes them per
issuer, with the brand's name and host and where each form posts, so nothing about one deployment is
baked in (G-6). A theme value that could close its `<style>` element is dropped. The typeface is
served from the OP's own origin: a sign-in page loading fonts from a third party tells it who signed
in where.

The **interaction screens** are rendered on the server with `renderToString`, each a form that
posts. The conformance suite drives them with a browser that runs little JavaScript, and
`packages/ui/src/screens.test.ts` pins the ids and texts its plan clicks on (NFR-C1). The one script
is `passkey.js`, loaded only by a screen offering passkeys: it unhides the passkey form, which stays
hidden without it, so every other path still posts as before (FR-I8). `assets.ts` builds the
stylesheet and the script once at startup, and `assets` serves them and the fonts by file name under
whatever route mounts it — `/assets/*` in the demo, `urls.stylesheet` and `urls.script` for another.
The account app imports the same WebAuthn JSON conversion from `@oidcraft/ui/passkeys`.

The **admin UI** (`src/admin`) is a client-rendered app on the same components. Its table and dialog
are `@oidcraft/ui`'s `UiDataTable` and `UiDialog`, which wrap the headless `@vuetify/v0`; the
server-rendered interaction screens never use it. Bun bundles `@vuetify/v0` only through
`@oidcraft/ui/bun-plugin`, which every app's `[serve.static]` lists: it patches two lines that only
Vite bundles as written. `utilities/instance.mjs` calls `helpers.mjs`'s `isArray` at its top level
while `helpers.mjs` imports it, and Bun's dev bundler hands a module still evaluating to its cyclic
importer as `null`; `constants/globals.mjs` reads `process.env.VITE_LOGGER_ENABLED`, which no bundler
but Vite replaces, so a production bundle reads `process` in the browser. A patch that no longer finds
its text fails the build. `bundles.test.ts` fails on any `process` read left in a production bundle;
the dev cycle shows only in a browser.

**The admin and account apps are clients of this OP.** Each signs in with `@oidcraft/vue` as its own
public client (`oidcraft-admin`, `oidcraft-account`), and each API introspects the bearer token
in-process as the resource server `oidcraft-api`. The admin API also requires an account in
`OIDCRAFT_ADMINS`, the decision FR-M1 leaves to the host; the account API acts only on the token's
own subject. The interaction routes answer consent for these first-party clients themselves.

**Sign-in is `@oidcraft/provider/accounts` (FR-I7, FR-I8).** A correct password for an account with
TOTP sets a signed, five-minute cookie bound to the interaction, which only the code step can finish,
with a TOTP code, a recovery code or one of that account's passkeys. A passkey alone signs in from
the login screen's button or the username field's autofill. `acr` is `mfa` after a second factor or
for a passkey and `pwd` otherwise, with RFC 8176 `amr` values: `hwk` and `user` for a passkey. The
account app adds, renames and removes passkeys; the admin app lists and removes them, for a device
that is lost or stolen, and sends a recovery link. Sign-up offers a passkey in place of the password,
then shows the recovery codes once before continuing; the login screen links a lost passkey to a
recovery-code form, whose answer is the reset screen. An account with no password manages its
recovery codes in the account app with a fresh passkey assertion, as one with TOTP does with a code.
`prompt=select_account` lists the accounts this browser signed in with, from another signed cookie.
A reset link is printed to the console where a deployment would email it.

`bundles.test.ts` bundles both browser apps the way `Bun.serve` does on first request, so a syntax
only the type checker accepts fails there rather than in a browser. `src/op` is the provider's
wiring — configuration, seed data, upstreams — and renders nothing.

**Realms are opt-in (`OIDCRAFT_REALMS=on`, FR-M4).** On, `OIDCRAFT_ISSUER` is the control plane — the
operator's admin and account apps, and the only site that brokers upstream — and each realm is a
subdomain of it, `acme.localhost:3001`, loopback on any machine (RFC 6761). The routes are built per
_site_ (a provider, its accounts and its branded screens). `provision` gives a realm its own SQLite
file and key pair under `data/realms/` and registers the demo relying party; `retire` deletes them.
With `OIDCRAFT_DB=postgres://…` a realm is the schema `realm_<id>` beside the control plane's
`public` (G-6). The admin's realm panel creates, disables and deletes realms, and `?realm=` aims every
other admin call at one realm.

**FAPI 2.0 is mixed by default (FR-C21).** With an https issuer, `src/fapi/demo.ts` seeds `fapi-demo`
under the profile beside the public clients and plays its part on the server, since a FAPI client is
confidential: `/fapi-demo` pushes the request with a client assertion and a DPoP proof, and its
callback redeems the code with DPoP and calls UserInfo. With an http issuer it is not seeded.
`OIDCRAFT_PROFILE=fapi2` puts the whole provider under the profile for the FAPI conformance plan.

**MCP is opt-in (`OIDCRAFT_MCP=on`, FR-C19, FR-C20).** `src/mcp/server.ts` serves an MCP server at
`/mcp` with one tool, `whoami`, through the official SDK's web-standard transport, stateless. A
request without a token gets the RFC 9728 401 pointing at its resource metadata; a token must be one
this OP issued for `/mcp`, checked by introspecting in-process as the resource's named server. It
also turns on registration and a metadata-document resolver, so an MCP client can register either
way.

### 8.2 `apps/demo-vue` — the demo relying party

Vue 3 + `@oidcraft/vue`, resolved from the workspace, so it proves that the binding in
`packages/vue` works. Run with `bun index.html` (§1.1). It uses the composables (`useOAuth`,
`useOAuthUser`) rather than the Vuetify component, so the demo carries no UI framework. `BUN_PORT`
sets the port.

### 8.3 `apps/demo-react` — the second relying party

React 19 + `@oidcraft/react`. It exists for the half of the binding the Vue demo cannot reach:
server rendering, where `useSyncExternalStore` must hand React a snapshot matching the client's first
paint, and where one instance per request is the difference between isolation and one user seeing
another's token.

### 8.4 `apps/demo-angular` — the toolchain island

Angular 22 + `@oidcraft/angular`, and **the one thing here that is not in the bun workspace**,
forced by two facts that conflict inside one install:

- `@angular/compiler-cli` requires `typescript >=6.0 <6.1`, and this workspace is on 7.
- Angular requires exactly **one** copy of `@angular/core` across an app and every library linked
  into it. Two fail as `Property '_desc' is protected but type 'InjectionToken<T>' is not a class
  derived from 'InjectionToken<T>'`.

bun hoists `@angular/compiler-cli` to the root, where it finds TypeScript 7. So the app has its own
`bun install` with **only** the compiler toolchain — `@angular/build`, `@angular/cli`,
`@angular/compiler-cli` and TypeScript 6 — while every runtime package, `@angular/core` included,
resolves upward to the root. Its `tsconfig.json` does not extend the base, because
`erasableSyntaxOnly` forbids the decorators a component needs.

`bun install` honours the exclusion; `bun run --filter='*'` does not — it globs directories and
reaches every script this app defines. So its real build is named `bundle`: as `build` it ran in
the root's parallel build beside `packages/angular`, whose tsdown `clean` empties the `dist/` the
Angular compiler reads, with no dependency edge to order them, and failed about one run in three.
`typecheck` keeps the plain name, because it runs after the build. `verify` covers its types; the
Angular compiler's template checking is `bun run build:angular`.

`packages/angular` contains no decorators, so it builds with tsdown on TypeScript 7 and depends on
none of this; the app is written against the `OAUTH` token (PLAN.md records why no component ships).

`build` in every workspace app is a typecheck, so `bun run build` at the root checks everything
without running three bundlers. `bundle` is the real build where there is one.

### 8.5 `apps/docs` — the documentation site, and the one Vite

VitePress, which brings Vite, and so the one deliberate break from §1.1: a docs site needs search,
an outline per page, dark mode and a static build for GitHub Pages, and Bun's bundler serves pages
rather than generating a site. Vite stays contained in this app, and VitePress is a Vue app, so it
adds no framework.

It renders the existing files rather than forking them: a page is an `@include` of
`REQUIREMENTS.md`, `ARCHITECTURE.md`, `PLAN.md` or a package README, or a page of its own that cites
them. Every code sample is one the suite ran: a README sample is pinned by a test, as
`minimal.test.ts` pins the provider's, and any other is a region of a test in `apps/docs/samples/`,
pulled in with `<<< @/samples/<file>.test.ts#<region>`. The configuration and error references are
generated from `packages/provider/src` at build time through `typescript/unstable/async` — unstable
by name, so a TypeScript bump can break them, loudly rather than with a wrong page.

A markdown-it plugin (`.vitepress/requirements.ts`) anchors every id `REQUIREMENTS.md` defines,
links every mention of one on any page to that anchor, and links each definition to `reference/ids`,
which lists the source files and tests citing it.

`bundle` is the real build, which `.github/workflows/docs.yml` deploys to GitHub Pages on every push
to `main`. The site tracks `main`: there are no versioned docs before 1.0.

## 9. Conventions

### 9.1 Environment variables

**Server-only code reads `Bun.env.X`. Only code the browser can reach reads `process.env.X`.**
They are the same object at runtime, so this is purely a safety boundary. Client builds inline
`OIDCRAFT_PUBLIC_*` and nothing else (`env: 'OIDCRAFT_PUBLIC_*'` in `build.ts` and in each app's
`[serve.static]`), so a server module leaking into the client graph fails the build instead of
baking a secret into a public file.

**Never `import.meta.env`**, and never a destructure or an indexed read — Bun aliases
`import.meta.env` to `process.env` at runtime, so SSR and the typechecker both accept it and only
the browser breaks. Only a whole literal `process.env.X` is substituted.

### 9.2 Code style

- **No commentary in code.** The exception is a fact the code cannot state and a reader could
  violate — an invariant, a constraint, a deliberate omission. One line, citing the `FR-*`/`NFR-*`
  id where the reasoning lives.
- **No explicit return type where it can be inferred.**
- **No file extension on a relative import.** `moduleResolution: "bundler"` resolves the `.ts`
  directly, and `vue-tsgo`'s resolver rejects the `.js` suffix outright.
- **A file using a Bun global carries `/// <reference types="bun" />` itself.**
- 140 columns, single quotes, no semicolons, no trailing commas, 2-space indent — `biome.json`
  settles it and `bun run format` applies it.

### 9.3 Per-app bunfig

`Bun.serve` reads plugins from the served entrypoint's directory. The root `bunfig.toml` does not
reach `apps/*`, so each app carries its own with `preload` and `[serve.static]`. This fails
silently when missing (§1.1).

## 10. Testing

The gate is `.github/workflows/ci.yml` on every push and pull request: `biome ci`, then `build`
(which runs `verify-entries`), then `typecheck`, then `bun test` — locally, `bun run verify`. Build
precedes typecheck because the apps resolve `@oidcraft/provider` through its exports map into
`dist/`, which a fresh clone lacks.

- **Adapter conformance** — `adapterConformance(create, { implements })`, the published
  `@oidcraft/adapter/conformance` entry, is one suite every adapter runs, covering the queries the
  protocol needs: expiry enforced by storage, `kind` as part of an artifact's identity, revocation
  by grant and by family removing that and nothing else, lookup by user code and by upstream
  session, prune, and the replay guard admitting a value once. An adapter that passes it is
  interchangeable with the others (FR-A4). It returns plain `{ name, run }` checks that throw, so a
  third-party adapter runs it under any runner (FR-A6); checks for `identities`, `credentials`,
  `passkeys` and `realms` run only for the stores `implements` names.
- **Unit** — `bun test` per package. Every `FR-C*` gets a test that exercises the wire format, not
  just the function behind it (NFR-C3).
- **Protocol conformance** — the OpenID Foundation suite's `basic`, `config` and FAPI 2.0 plans gate
  CI (NFR-C1), as the `conformance` job in `ci.yml`. `conformance/README.md` holds how to run it and
  each refusal with its clause.
- **Metadata conformance** — `metadata.test.ts` checks the discovery document against OIDC
  Discovery 1.0 §3 and RFC 8414 §2 and against behaviour: every advertised endpoint answers, every
  advertised algorithm has a key, a disabled feature is neither advertised nor routed. It is not
  certification.
- **Brokering** — a second oidcraft instance is the upstream in tests, so both legs run without
  depending on Google being up.

## 11. Publishing

Eleven packages, `@oidcraft/*` (§2.1), each built by `tsdown` to ESM with `.d.mts` types and published
by `.github/workflows/publish.yml` from a GitHub release tagged `<name>@<version>` — for example
`@oidcraft/provider@0.1.0`. The workflow checks the tag against that package's `package.json` before
building anything.

Trusted publishing (OIDC) from GitHub Actions needs `permissions: id-token: write`, no
`NODE_AUTH_TOKEN`, and `actions/setup-node` with `registry-url` set. `bun pm pack` builds the tarball,
because it rewrites `workspace:^` to the version it names and npm does not; `npm publish` uploads it,
because only npm does trusted publishing and provenance.

**Order matters.** A binding names a `@oidcraft/client` and `@oidcraft/core` version, the provider a
`@oidcraft/core` and a `@oidcraft/adapter` one, `@oidcraft/adapter` a `@oidcraft/core` one, and each
adapter a `@oidcraft/adapter` one; those must be on npm before it is.

**The first publish of each package is manual**, with a login or token: npm's trusted-publisher
configuration only exists once a version has been published, so OIDC cannot bootstrap a new package
(npm/cli#8544). Configure `npm trust github` after that first release. Scoped names skip npm's
server-side similarity check on new unscoped names; the old unscoped names are in PLAN.md.
