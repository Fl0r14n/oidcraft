# Plan

What is left, in order. `REQUIREMENTS.md` says what it must do, `ARCHITECTURE.md` how.
This file is working state: tick items off and add notes as work lands.

## Status

**A working OpenID Provider for the authorization code flow, plus identity brokering.** 177 tests.

Done: configuration validated at construction, discovery, JWKS and key rotation, the code grant with
mandatory PKCE, interaction suspend/resume with remembered consent, token issuance with refresh
rotation and replay revocation, UserInfo, revocation, introspection, RP-initiated and back-channel
logout, the `KvStore` derivation, memory and Drizzle/SQLite adapters passing one shared conformance
suite, the Node bridge, and an identity broker exercised against a live second instance.

**Not yet a complete OP.** The big absences are the sender-constraining and request-integrity
features (DPoP, PAR, JAR), the remaining grants (device, token exchange, CIBA), dynamic
registration, pairwise subjects, the management API and admin UI, and Postgres. Federation works but
is not wired into the authorization endpoint, so a host drives `start`/`complete` around its own
interaction rather than the OP choosing an upstream itself.

**Nothing has been run against the OpenID Foundation conformance suite.** Until that happens,
"RFC-compliant" is an intention, not a measurement (NFR-C1).

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
- [ ] The same adapter against Postgres
- [ ] `oidcraft/adapters/kysely`
- [ ] OpenID Foundation conformance suite in CI: `basic`, `config` (NFR-C1)
- [x] `oidcraft/runtimes/node` HTTP bridge, tested against a real node:http server (FR-R3)
- [x] Capability gating: mTLS methods are refused at construction where no certificate can be
      supplied, and absent from discovery (FR-R5, `G-8`)
- [ ] Smoke tests for `oidcraft/runtimes/{bun,deno,workerd}` — written but only `node` is exercised

## M3 — federation

- [x] `UpstreamProvider` discovery and the RP leg (FR-F1)
- [x] Handoff: single-use suspend/resume across the upstream round trip (FR-F3)
- [x] Home-realm discovery (FR-F4); linking policies (FR-F5)
- [x] Claim mapping (FR-F7); provenance carried on the identity (FR-F6)
- [x] Test upstream: a second oidcraft instance (ARCHITECTURE.md §10)
- [ ] Wire the broker into the authorization endpoint's policy step, so an upstream round trip is
      one interaction rather than the host stitching `start`/`complete` together
- [ ] Logout propagation both ways (FR-F8); `prompt=login` / `max_age` passthrough (FR-F9)

## M4 — the rest of the protocol

- [x] Revocation, introspection (FR-C8); RP-initiated and back-channel logout (FR-C11)
- [x] DPoP (FR-C13): bound access and refresh tokens, `ath`/`htm`/`htu` checks, jti replay guard
- [ ] DPoP nonces (`DPoP-Nonce`, `use_dpop_nonce`)
- [ ] PAR, JAR (FR-C12)
- [ ] Device grant (FR-C7); DCR (FR-C9); pairwise subjects (FR-C18)
- [ ] Token exchange (FR-C2); RAR (FR-C15); step-up (FR-C16); CIBA (FR-C17)

## M5 — batteries

- [x] Reference login and consent screens (FR-I3), remembered consent (FR-I4)
- [ ] The remaining screens: account selection, upstream selection, device code, logout
- [ ] Management API (FR-M1) and admin UI (FR-M2)
- [x] First manual publish: `oidcraft@0.0.1` claimed the name — the similarity check cleared
- [ ] `npm trust github` registration, so releases publish from CI (ARCHITECTURE.md §11)
- [ ] Docs site

## Decisions waiting on an answer

`G-1` OpenID Federation 1.0 · `G-2` how much of the account the library owns · `G-3` FAPI 2.0 ·
`G-4` upstream SAML · `G-5` TypeORM · `G-6` multi-tenancy · `G-7` Drizzle v1 ·
`G-8` mTLS on Bun
