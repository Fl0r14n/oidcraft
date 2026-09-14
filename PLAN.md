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
