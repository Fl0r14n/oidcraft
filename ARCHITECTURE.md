# Architecture

How oidcraft is built. `REQUIREMENTS.md` says what it must do; every section here cites the
`FR-*`/`NFR-*` ids it satisfies, and those ids are the contract between the two files.

## 1. Stack

| Choice | Version | Why |
| --- | --- | --- |
| **Bun** | ≥ 1.4 | Workspaces, test runner, bundler and HTTP server in one tool. The *development* runtime; the published packages target no runtime in particular (FR-R1). |
| **TypeScript** | 7.0.x | `tsc` for `.ts`, `vue-tsgo` for packages with SFCs. |
| **Tailwind** | 4.3.x | Styling for both apps, via `bun-plugin-tailwind`. No other CSS pipeline. |
| **@vuetify/v0** | 1.2.x | Headless Vue primitives, in the **admin surface only** (§8.1). Vue 3.5 is its only dependency. |
| **Biome** | 2.5.x | Lint and format. `biome.json` settles formatting; it is not a matter of preference. |
| **jose** | ^6 | The only runtime dependency. WebCrypto-backed, runtime-agnostic (NFR-D4). |
| **openid-client** | ^6 | Optional peer, confined to the `./federation` entry (§2.2). |
| **tsdown** | 0.23.x | Library build: seven ESM entries with `.d.mts` types (§2.2). |
| **Drizzle / Kysely** | 0.45 / 0.28 | First-party adapters (FR-A4). Optional peers, never bundled (§2.2). |

### 1.1 No bundler, no build step

Neither app has one. `bun index.html` **is** the client: Bun's dev server bundles the Vue SFCs,
compiles Tailwind, inlines `OIDCRAFT_PUBLIC_*` and serves the page with HMR. The server app runs
from source, because Bun executes TypeScript. There is no Vite, no `Bun.build` script, no `dist/`,
and nothing to keep in sync between a dev path and a build path.

Two sharp edges, both measured here rather than assumed:

- **Plugins come from the bunfig next to the served entrypoint**, via `[serve.static]` — not the
  root one. Each app carries its own `bunfig.toml`. Deleting it does not error; it silently serves
  a `.vue` import as a path string and renders a blank page.
- **No `@/` path alias in the apps.** `tsconfig.json` `paths` resolve under `bun build` but not
  under the dev server, which resolves the specifier relative to the importing file and fails with
  `ENOENT … /src/@/App.vue`. App-internal imports are relative. Measured 2026-09-12 against Bun
  1.4.0; recheck before reintroducing the alias.

If a real production bundle is ever wanted — minified, content-hashed, served by something other
than Bun — note that `bun build` **the CLI** takes no plugins, so it would have to be a `build.ts`
calling `Bun.build` directly. Nothing needs that today.

### 1.2 TypeScript 7 and Vue

`vue-tsc` still requires `typescript/lib/tsc` and does not run against TypeScript 7, so any package
containing `.vue` files type-checks with `vue-tsgo` instead. Packages without SFCs use `tsc` —
TypeScript 7 ships its compiler under that name, and `tsgo` is the older `@typescript/native-preview`
binary, which is still on a `7.0.0-dev` tag and is not what the `typescript` package installs.

## 2. Workspace

```
packages/oidcraft/          one published package, seven entries
  src/index.ts              .                     the OP. fetch in, fetch out, no I/O
  src/federation/           ./federation          the relying-party leg — upstream brokering
  src/interaction/          ./interaction         login/consent policy types
  src/node/                 ./node                node:http / Express / Fastify bridge
  src/adapters/memory/      ./adapters/memory     tests and development only
  src/adapters/drizzle/     ./adapters/drizzle    Postgres, SQLite
  src/adapters/kysely/      ./adapters/kysely     Postgres, SQLite, MySQL
apps/
  server                    the reference OP: mounts the core, the login screens and the admin UI
  client                    the demo relying party: Vue 3 + vue-oidc
```

### 2.1 One package, not seven

`oidcraft` ships as a single package with subpath exports, and `drizzle-orm`, `kysely` and
`openid-client` are **optional** peer dependencies — nobody installing it for Kysely pulls Drizzle.

The reason is the adapter contract. It is the part of this library most likely to churn before 1.0,
and it is exactly the coupling that makes a split painful: separate versioning puts consumers on
`@oidcraft/core@0.5` with `@oidcraft/adapter-drizzle@0.3` and a type error they cannot resolve.
Auth.js lives that; `oidc-provider` and `better-auth` do not, because they are single packages.
`drizzle-orm` itself is the closest precedent — dozens of driver adapters as subpath exports with
optional peers, not as separate packages.

Two secondary reasons. Going one package to several later is mechanical; going several to one is a
breaking change for every consumer, so the merged shape is the reversible one. And npm's trusted
publishing cannot bootstrap a *new* package — the configuration only exists once a version is
published — so every extra package is another manual first publish and another `npm trust github`
run behind a browser OTP.

What the split was actually buying is a hard wall stopping the core from importing `openid-client`.
`verify-entries.ts` replaces it (§2.2).

### 2.2 Entry invariants

Each optional peer is confined to the one entry that owns it; that is what keeps it optional rather
than a tax on every consumer. Nothing enforces this at build time, and every way of breaking it
fails silently — a leaked peer surfaces only as a resolution error in a consumer who never installed
it, and a core type inlined into an entry compiles fine while shipping a second copy that drifts.

`verify-entries.ts` runs after `build` and asserts, per entry: no optional peer it does not own, in
either the JS or the `.d.mts`; no `node:` builtin outside the `./node` entry (FR-R1); no redeclared
core type; and — once an entry has runtime code — that it imports the root by package name rather
than inlining a second copy of the core. Entries that are still types-only compile to `export {};`,
so their runtime checks are reported as pending rather than passing quietly.

**Publishing unscoped carries one risk.** npm rejects new unscoped names too similar to an existing
one, server-side on the `PUT`, where neither `npm view` nor `npm publish --dry-run` sees it coming —
and `oidc` is taken. `oidcraft` is four characters longer and a real blend, so it should clear, but
the first publish is the test. The fallback is a scoped single package, which skips the check.

## 3. The core

### 3.1 Request pipeline

The root entry exposes one function of `(Request, RequestContext) => Promise<Response>`. It is
the whole surface. On Bun, Deno and workerd that mounts directly into the runtime's server with no
adapter; the `./node` entry exists only to translate `IncomingMessage`/`ServerResponse` into that
shape for node:http hosts (FR-R3).

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
verified client certificate for mTLS, the client IP, and the deployment's public origin
(FR-R4, NFR-S6). The issuer is configuration and is never derived from a header.

### 3.2 What the core does not do

No HTML. No cookies beyond the session cookie whose name and attributes the host configures. No
timers, no background sweeps, no connection pool, no process-level cache that survives a request
(FR-A1, NFR-P3). Two processes behind a load balancer behave identically to one, which is the
property that makes horizontal scaling and serverless hosting the same thing.

## 4. The adapter layer

`packages/oidcraft/src/adapter.ts` is the contract. Storage is **a set of narrow capability stores**,
not one table keyed by a model-name string:

| Store | Holds |
| --- | --- |
| `ClientStore` | Registered clients. `create`/`update`/`destroy` are optional — omitting them disables DCR at runtime (FR-C9). |
| `ArtifactStore` | Codes, access and refresh tokens, device codes, PAR and CIBA requests, registration access tokens. |
| `SessionStore` | The end-user's authenticated session at the OP, including its upstream provenance (FR-F6). |
| `GrantStore` | Durable consent: what an account allowed a client, surviving token revocation (FR-I4). |
| `AccountStore` | The host's users. Claims are resolved per request, never cached at login (FR-C5). |
| `KeyStore` | Signing keys, newest first (FR-C10). |
| `ReplayGuard` | One-shot values: `jti`, DPoP proofs, upstream nonces (NFR-S5). |
| `FederatedIdentityStore` | `(provider, subject) → account` links. Optional; only brokering deployments need it. |

### 4.1 Why not `oidc-provider`'s shape

`oidc-provider`'s adapter is a single class instantiated per model name, with
`upsert`/`find`/`findByUid`/`findByUserCode`/`consume`/`destroy`/`revokeByGrantId` and an untyped
`AdapterPayload` for every one of them. It works, and every implementation of it in the wild ends
up as one table of `(kind, id, payload jsonb)` — which means the queries the protocol actually
needs (revoke by grant, find by user code, expire a range) run against JSON extraction instead of
an index, and the payload's type is `any` at every call site.

Splitting by capability makes each method's payload a real type, lets a relational adapter use
real columns and indexes (FR-A5), and lets a deployment implement only what it uses. `KvStore`
(FR-A3) keeps the simple case simple: implement four methods and `fromKv` derives the rest.

### 4.2 Schema ownership

An adapter ships migrations the host runs. The library never creates or alters a table at boot —
a library that migrates a production database on import is a library that migrates it during a
rolling deploy, from several processes at once.

## 5. Federation

### 5.1 Two things named federation

**Identity brokering** is what oidcraft implements (FR-F*): it is the OP its clients see, and at
the same time a relying party at one or more upstream OPs. Downstream clients never learn an
upstream exists.

**OpenID Federation 1.0** — entity statements, trust chains, trust anchors, automatic registration
across a multilateral trust fabric — is a different protocol solving a different problem
(who may talk to whom, across organisations that never bilaterally registered). It is deferred
(`G-1`) and nothing in the core should assume it away.

### 5.2 The two legs

```
  client ──authorization request──▶ oidcraft ──▶ interaction: which upstream? (FR-F4)
                                       │
                                       ├── oidcraft/federation is the RP:
                                       │     authorization request ──▶ upstream OP
                                       │     callback ◀── code + state + PKCE verifier
                                       │
                                       ├── claim mapping (FR-F7), account link (FR-F5)
                                       ├── local session records `idp` + upstream session (FR-F6)
                                       │
  client ◀──────code──────────────────┘  the downstream interaction resumes
```

The handoff (`src/federation/types.ts`) carries `state`, `nonce`, the PKCE verifier and **the id of
the downstream interaction it resumes**. That last field is what makes this a suspend/resume of one
authorization request rather than two unrelated flows stapled together — and it is why the handoff
must be single-use, expiring and bound to the browser that started it (FR-F3).

### 5.3 Why brokering lives in the core, not in the app

Four things reach into the protocol core and cannot be bolted on from outside:

- **Session provenance.** `idp`, `acr`, `amr` and `auth_time` in a brokered ID token are the
  upstream's answers, so `SessionStore` must carry them (FR-F6).
- **Re-authentication.** `prompt=login`, `max_age` and a raised `acr_values` have to force a fresh
  *upstream* authentication. A local session cannot satisfy them on its own (FR-F9).
- **Logout.** An upstream back-channel logout must terminate the local sessions it produced, which
  triggers this OP's back-channel logout to its own clients. Hence
  `SessionStore.findByUpstreamSession` (FR-F8).
- **Home-realm discovery.** Choosing the upstream from `login_hint`, `acr_values` or the client's
  allowed list happens inside the authorization endpoint's policy step (FR-F4).

A deployment that keeps brokering in the application layer gets the happy path and none of these.

### 5.4 Pure-proxy mode

With no local credentials at all, oidcraft is a protocol-normalising proxy: one issuer, one set of
client registrations, one token format, several upstreams behind it. `sub` is then derived from
`(provider, subject)` and is stable per account — never passed through from an upstream, whose
`sub` is only unique within that upstream.

### 5.5 The linking hazard

Matching a brokered identity to a local account by email address is account takeover the moment an
upstream does not verify addresses, or lets a user change one. The default is `(provider, subject)`
and nothing else (FR-F5, NFR-S8). `verified-email` exists, requires `email_verified` from the
upstream, and is still a deliberate decision an operator has to make. `interactive` — prove control
of the existing account, then link — is the honest answer for a consumer-facing deployment.

### 5.6 Upstream tokens

Keeping an upstream's access token so downstream code can call that upstream's API makes the
deployment a credential store for another system. Off by default, opt-in per provider, encrypted
at rest, never handed to a downstream client without an explicit API call (FR-F10, NFR-S9).

## 6. Interaction

The authorization endpoint decides what it can and, when it cannot finish, emits an
`InteractionRequest` and redirects (FR-I1). The interaction app — any HTTP app, including the
reference one — answers with an `InteractionResult`, and the core re-evaluates the original
request against it, free to demand another interaction (FR-I2).

This is `oidc-provider`'s model, and it is the right one: it keeps HTML out of the protocol core
and lets a host replace the screens entirely. The difference is that oidcraft ships the screens
(FR-I3) and the consent-memory model (FR-I4) instead of leaving both as an exercise.

## 7. Administration

The root entry exposes the management surface as fetch handlers over clients, grants, sessions,
keys and upstreams (FR-M1). **The library never decides who is an administrator** — the host mounts
these behind its own authentication, and the reference app does so behind its own admin session.
Writes emit audit events the host routes somewhere; the library persists none of them (FR-M3).

## 8. Apps

### 8.1 `apps/server` — the reference OP

One `Bun.serve` process mounting the core's fetch handler, the reference interaction screens and the
admin UI. It is the deployment the conformance suite runs against (NFR-C1), which is the reason it
exists: a reference that is never executed is a reference that is wrong.

**The two surfaces get different answers on components.**

The **login, consent and device screens** use Tailwind and plain markup, no component library. They
are a handful of forms, they exist to be forked (FR-I3), and the `./interaction` entry must not put a
UI peer dependency on every consumer that wants the policy layer.

The **admin UI** uses `@vuetify/v0`. Client CRUD, session inspection and grant revocation are
sorting, pagination, selection, confirmation dialogs and validated forms — expensive to hand-roll
and easy to get wrong for accessibility. `DataTable`, `Dialog`/`AlertDialog`, `Combobox`/`Select`
and `Form` + `createValidation` cover it. It is headless, so Tailwind still does all the styling and
nothing imposes a look on an operator who replaces these screens.

### 8.2 `apps/client` — the demo relying party

Vue 3 + `vue-oidc`, ported from that library's own sample app. It proves the OP against a real,
independently written client rather than against a test harness that shares its assumptions.

Run with `bun index.html` and nothing else (§1.1). It uses `vue-oidc`'s composables (`useOAuth`,
`useOAuthUser`) rather than its Vuetify component, so the demo carries no UI framework at all — a
login button and a claims list do not need one. `BUN_PORT` sets the port.

`build` in both apps is a typecheck, kept under that name so `bun run build` at the root still
checks everything.

## 9. Conventions

### 9.1 Environment variables

**Server-only code reads `Bun.env.X`. Only code the browser can reach reads `process.env.X`.**
They are the same object at runtime, so this is purely a safety boundary. Client builds inline
`OIDCRAFT_PUBLIC_*` and nothing else (`env: 'OIDCRAFT_PUBLIC_*'` in `build.ts` and in each app's
`[serve.static]`), so a server module that leaks into the client graph fails the build instead of
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

- **Unit** — `bun test` per package. Every `FR-C*` gets a test that exercises the wire format, not
  just the function behind it (NFR-C3).
- **Adapter conformance** — one shared suite every adapter runs, so memory, Drizzle and Kysely are
  provably interchangeable.
- **Protocol conformance** — the OpenID Foundation suite (a Docker image) runs in CI against
  `apps/server` for the `basic`, `config` and `dynamic` OP profiles. Red suite, failed build
  (NFR-C1).
- **Federation** — a second oidcraft instance is the upstream in tests. Brokering to ourselves
  exercises both legs without depending on Google being up.

## 11. Publishing

One package, `oidcraft`, built by `tsdown` to ESM with `.d.mts` types. Trusted publishing (OIDC)
from GitHub Actions, which needs `permissions: id-token: write`, no `NODE_AUTH_TOKEN`, and
`actions/setup-node` with `registry-url` set.

**The first publish must be manual**, with a login or token: npm's trusted-publisher configuration
only exists once a version has been published, so OIDC cannot bootstrap a new package
(npm/cli#8544). Configure `npm trust github` after that first release — once, not seven times (§2.1).
