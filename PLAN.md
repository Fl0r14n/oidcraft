# Plan

What is left, in order. `REQUIREMENTS.md` says what it must do, `ARCHITECTURE.md` how.
This file is working state: tick items off and add notes as work lands.

## Status

**M3 is most of the way there.** The broker does both legs against a live upstream — discovery,
PKCE, the code exchange, claim mapping, single-use handoffs, linking policies. What is left is the
wiring: the authorization endpoint does not yet choose an upstream by itself, so a host calls
`start` and `complete` around its own interaction. Logout propagation (FR-F8) and the `prompt=login`
passthrough (FR-F9) are not built.

**M4 is under way.** Revocation, introspection and logout are implemented, so every endpoint the
default configuration advertises now answers for real — a test asserts that, rather than trusting
it. Back-channel logout tokens are minted and handed to the host: the core performs no I/O, and a
fan-out with retries does not belong in a request.

**M1 is done.** The code grant works end to end: a browser completes login and consent, exchanges
the code with PKCE, and receives an ID token that verifies against the published JWKS. Replaying a
code or a refresh token revokes the grant. 107 tests.

Still open before this is a usable OP: revocation and introspection are configured but answer 501,
logout is not implemented, and `apps/client` has not been driven against it in a browser.

**M0 is done.** `createProvider` validates its configuration at construction, routes, and serves a
real discovery document and JWKS; `fromKv` derives a complete `Adapter` from four key-value methods,
and the memory adapter passes the shared conformance suite. 78 tests. `apps/server` runs it.

Nothing of the protocol proper exists yet: the authorization, token, userinfo and logout endpoints
answer 501 and point here. M1 is the code grant.

## M0 — foundation

- [x] CI: `biome ci`, build + `verify-entries`, typecheck, `bun test` on push and PR
- [x] `exports.test.ts`: the exports map, the source tree and the build entries agree

- [ ] Root entry: config construction with validation (NFR-D2), route table, error responses
- [ ] `KeyStore` + JWKS endpoint + discovery document (FR-C6, FR-C10)
- [ ] `oidcraft/adapters/memory` and the shared adapter-conformance suite (FR-A3, FR-A4)
- [ ] `fromKv` derivation over `KvStore`

## M1 — the code grant

- [x] Authorization endpoint, `code` only, PKCE mandatory (FR-C1, FR-C3)
- [x] Interaction suspend/resume (FR-I1, FR-I2) and remembered consent (FR-I4)
- [x] Token endpoint: `authorization_code`, `refresh_token`, with rotation and replay revocation
      (FR-C2, FR-T3, FR-T4)
- [x] Client authentication: `none`, `client_secret_basic`, `client_secret_post` (FR-C4)
- [x] UserInfo (FR-C5); `iss` in the authorization response (FR-C14)
- [x] `apps/server` serves a real OP with reference login and consent screens

## M2 — storage and conformance

- [ ] `oidcraft/adapters/drizzle` with migrations and real indexes (FR-A5)
- [ ] `oidcraft/adapters/kysely`
- [ ] OpenID Foundation conformance suite in CI: `basic`, `config` (NFR-C1)
- [x] `oidcraft/runtimes/node` HTTP bridge, tested against a real node:http server (FR-R3)
- [ ] Context providers: `oidcraft/runtimes/{bun,deno,workerd}`, one smoke test each (FR-R3, FR-R4)
- [ ] Capability gating: disable mTLS methods where no certificate can be supplied (FR-R5, `G-8`)

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
- [ ] PAR, JAR (FR-C12); DPoP (FR-C13)
- [ ] Device grant (FR-C7); DCR (FR-C9); pairwise subjects (FR-C18)
- [ ] Token exchange (FR-C2); RAR (FR-C15); step-up (FR-C16); CIBA (FR-C17)

## M5 — batteries

- [ ] Reference interaction screens (FR-I3), consent memory (FR-I4)
- [ ] Management API (FR-M1) and admin UI (FR-M2)
- [x] First manual publish: `oidcraft@0.0.1` claimed the name — the similarity check cleared
- [ ] `npm trust github` registration, so releases publish from CI (ARCHITECTURE.md §11)
- [ ] Docs site

## Decisions waiting on an answer

`G-1` OpenID Federation 1.0 · `G-2` how much of the account the library owns · `G-3` FAPI 2.0 ·
`G-4` upstream SAML · `G-5` TypeORM · `G-6` multi-tenancy · `G-7` Drizzle v1 ·
`G-8` mTLS on Bun
