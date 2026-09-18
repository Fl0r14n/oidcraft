# Plan

What is left, in order. `REQUIREMENTS.md` says what it must do, `ARCHITECTURE.md` how.
This file is working state: tick items off and add notes as work lands.

## Status

**Every `FR-*` on the plan is implemented.** 366 tests, and `bun run verify` is the gate.

The authorization code grant with mandatory PKCE, interaction suspend/resume, token issuance with
rotation and replay revocation, UserInfo, revocation, introspection, logout in both directions,
DPoP with nonces, PAR, JAR by value, dynamic client registration with RFC 7592 management, the
device grant, CIBA in poll and ping, token exchange, RAR, step-up, pairwise subjects, identity
brokering with home-realm discovery chosen by the provider, three storage adapters passing one
conformance suite, four runtime context providers, a management API and an admin UI.

### What is NOT done, and will not be silently forgotten

**Nothing has been run against the OpenID Foundation conformance suite** (NFR-C1). Every compliance
claim here rests on a reading of the specs and tests written by the same person who wrote the code,
which is not the same thing as certification. The suite publishes no image; it needs a Maven build
and an OP it can reach. `conformance/` holds the plan and a runner for whoever does that.

**No deployment has run this in production**, against a real relying party that was not also written
here, or under any load.

### Decided against, rather than pending

- **JAR by reference** (`request_uri` pointing at the client's own server) — resolving it means the
  core fetching a URL the client chose, which is outbound I/O it does not do (FR-A1). A host that
  needs it resolves and pushes the result. See `REQUIREMENTS.md` FR-C12.
- **A Postgres schema shipped untested** — the Drizzle adapter's query logic is dialect-agnostic but
  its schema module is not, and shipping a `pg-core` schema nothing has executed would be a claim
  rather than a feature. SQLite is tested in-process; Postgres is a schema file away for whoever
  needs it and can run it.
- **Editing upstream providers from the admin UI** — an issuer and client credentials are deployment
  configuration, not runtime state. The admin shows what is configured.
- **CIBA push mode**, **OpenID Federation 1.0** trust chains (`G-1`), and **upstream SAML** (`G-4`).

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
- [x] `apps/server` serves a real OP with reference login and consent screens

## M2 — storage and conformance

- [x] `oidcraft/adapters/drizzle` (SQLite) with real columns and indexes, passing the shared
      conformance suite; `explain query plan` asserts revocation and the user-code lookup use
      their indexes (FR-A5)
- [~] Postgres — deliberately not shipped untested; see the status section
- [x] `oidcraft/adapters/kysely`, passing the same conformance suite as memory and Drizzle
- [x] `metadata.test.ts`: the discovery document against OIDC Discovery 1.0 §3 and RFC 8414 §2,
      cross-checked against behaviour. **Not certification** — see `conformance/README.md`
- [x] `conformance/` harness: plan configuration and a runner, for a suite built from source
- [ ] Actually run the OpenID Foundation suite: `basic`, `config`, `dynamic` (NFR-C1). It publishes
      no image, so this needs a Maven build and an OP the suite can reach
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
- [ ] `npm trust github` registration, so releases publish from CI (ARCHITECTURE.md §11)
- [ ] Docs site — **after** the review and the conformance run; requirements below

## `FR-*` coverage

Every functional requirement in `REQUIREMENTS.md` is implemented, including the six that an audit
against behaviour — rather than against these checkboxes — found missing after the list said
otherwise: FR-C4's mTLS methods, FR-C5's signed and encrypted UserInfo, FR-C11's front-channel
logout, FR-C13's certificate-bound tokens, FR-C16's resource-server challenge, and FR-T2's JWT
access tokens.

`metadata.test.ts` exercises every advertised value rather than reading it, which is the check that
was missing when discovery advertised three things the code refused.

What is *not* claimed: see the status section. Implemented is not the same as certified, and no
`FR-*` here has been checked by anything but its author and its tests.

## Next, in this order

1. **A manual in-depth review.** Nothing here has been read by anyone other than its author. 366
   passing tests say the code does what its tests say, which is a weaker statement than it looks.
2. **The OpenID Foundation conformance suite** (NFR-C1) — `basic`, `config`, `dynamic`. See
   `conformance/README.md`: no published image, so it needs a Maven build and an OP it can reach.
   Until it is green, "RFC-compliant" stays an intention.
3. **The docs site**, once there is something certified to document.

## Docs site — requirements

Recorded now so the decisions are not re-made later. Not started.

**Samples are executed, never written.** Every code block comes from a file the test suite runs and
is extracted at build time, the way `minimal.test.ts` already does for the README example. A rotted
sample in a charting library is an annoyance; in an auth library it is a security instruction that
no longer holds.

**The landing page says what is not done.** "Not run against the OpenID Foundation suite. Not used
in production" belongs above the fold, not in a FAQ. Docs sites are where that discipline erodes
into "production-ready" and a grid of green ticks, so this is an acceptance criterion rather than an
intention. If the site cannot say it on page one, it is not ready to exist.

**The requirement ids are the spine.** There are 82 `FR-*`/`NFR-*`/`G-*` ids and 62 of them are
cited in the source. `FR-C3` should be a link — to the requirement, to where it is implemented, to
the test that proves it. That is the thing no other provider's documentation has, and the content
already exists.

**It renders the existing files; it must not fork them.** `ARCHITECTURE.md`, `REQUIREMENTS.md` and
`PLAN.md` stay the source. Two copies of a requirement is strictly worse than one.

Pages that do not exist yet and have to be written:

- The interaction contract — every integrator implements login and consent, and it is currently only
  described in `FR-I*`. This is the page that decides whether someone succeeds.
- Adapter authoring: `KvStore` in four methods, or the full `Adapter`, and how to run the shared
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

**Open decision: the generator.** `apps/*` have no Vite because Bun's bundler sufficed for bundling
two small apps, which does not automatically extend to a docs generator. VitePress in `apps/docs`
with its Vite contained there is the recommendation; Starlight is the alternative if Vue should stay
out of the docs toolchain. Worth breaking the pattern deliberately and writing down why, rather than
building a worse site to preserve a rule that was about something else.

## Decisions waiting on an answer

`G-1` OpenID Federation 1.0 · `G-2` how much of the account the library owns · `G-3` FAPI 2.0 ·
`G-4` upstream SAML · `G-5` TypeORM · `G-6` multi-tenancy · `G-7` Drizzle v1 ·
`G-8` mTLS on Bun

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
- **`UpstreamProvider.tokenAuthMethod`** picks `client_secret_post`, `client_secret_basic` or `none`.
  Before it was whatever `openid-client` defaulted to.
- **FR-F11 is real**: an unreachable upstream, a refusal on the redirect, a wrong `iss` and a failed
  ID token each become a distinct `OAuthError` with the clause that was violated.

`metadata.contract.test.ts` pins the discovery document this OP *writes* to the type the RP core
*reads*, so renaming an endpoint here is a compile error rather than someone's runtime `undefined`.

## The monorepo: four libraries, one protocol core

Decided 2026-09-18, not started. `vue-oidc`, `ngx-oauth` and `react-oauth-oidc` move into this
workspace and their GitHub repositories are archived. The **npm packages keep their names and their
users** — only the repositories are deprecated.

The reason is not tidiness. Read side by side, the three libraries have already converged on the
same module boundaries, independently:

| module | vue-oidc | react-oauth-oidc | ngx-oauth |
| --- | --- | --- | --- |
| `config` `fetch` `functions` `jwt` `token` `types` `user` | yes | yes | yes |
| storage | `ref.ts` | `storage.ts` | `storage.ts` |
| flows | `flows.ts` | `flows.ts` | `oauth.ts` |
| optional UI `component/` | Vuetify | yes | Material |

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
workspace-private package leaks into a published bundle.

### Decided

- **`ngx-oauth` drops `ng-packagr`.** Its library has no decorators — `@Injectable`, `@NgModule` and
  `@Component` appear only in the sample app and the optional login component — so it satisfies
  `erasableSyntaxOnly` and builds with tsdown like every other package here. The Angular *sample*
  still needs the Angular CLI, which is a deliberate exception to §1.1's no-bundler rule for apps.
- **Order: vue-oidc, then React, then Angular.** vue-oidc is the reference implementation, React is
  the closest in shape and already on tsdown, and Angular goes last so the signal abstraction has
  been validated against two frameworks before it meets the one with its own toolchain.

### What would make `@oidcraft/core` a published package

It is `private: true` today and that is a deferred decision, not a closed one. What argues for
publishing, once the client libraries are actually here:

- **Propagation.** A fix to the `iss` or nonce handling currently means publishing four packages and
  every user upgrading four. Published, it is one release that anyone on a caret range picks up.
- **Four consumers, not two.** The bundling case was obvious at two.
- Svelte, Solid and vanilla come free rather than on request.

What was *not* a real argument against it, and should not be reused: the §2.1 version matrix. That
pain is specific to **peer** dependencies, where the consumer reconciles two versions. As an
ordinary dependency there is nothing to reconcile. If it is published, `NFR-D4` needs one word —
zero *third-party* runtime dependencies beyond `jose` — because the core's own tree is `jose` alone.

### Still open

- **`vue-oidc` still has its own copy** of this code. It moves into `packages/` and onto
  `packages/core` with the Angular and React bindings; until it does, the two copies can drift, and
  the four fixes above exist only here.
- **Both halves carry their own `base64url`.** Four lines, duplicated between the OP and the RP core
  because the alternative is the RP core depending on the provider. `verify-entries.ts` compares
  against the root's *exported* names for exactly this reason — two independent libraries are
  entitled to share a private helper's name.
- **Introspection still authenticates with Basic unconditionally.** `tokenAuthMethod` covers the
  token, refresh and revocation endpoints, where the choice actually varies between providers.
