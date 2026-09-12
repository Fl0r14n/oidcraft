# Plan

What is left, in order. `REQUIREMENTS.md` says what it must do, `ARCHITECTURE.md` how.
This file is working state: tick items off and add notes as work lands.

## Status

Scaffold only. The workspace, the toolchain and the adapter contract exist; no protocol code does.
`packages/*/src` are stub barrels proving the workspace wiring, except
`packages/core/src/adapter.ts` and `packages/federation/src/types.ts`, which are the real contracts
everything else is written against.

## M0 — foundation

- [ ] `@oidcraft/core`: config construction with validation (NFR-D2), route table, error responses
- [ ] `KeyStore` + JWKS endpoint + discovery document (FR-C6, FR-C10)
- [ ] `@oidcraft/adapter-memory` and the shared adapter-conformance suite (FR-A3, FR-A4)
- [ ] `fromKv` derivation over `KvStore`

## M1 — the code grant

- [ ] Authorization endpoint, `code` only, PKCE mandatory (FR-C1, FR-C3)
- [ ] Interaction suspend/resume (FR-I1, FR-I2)
- [ ] Token endpoint: `authorization_code`, `refresh_token`, with rotation and replay revocation
      (FR-C2, FR-T3, FR-T4)
- [ ] Client authentication: `none`, `client_secret_basic`, `client_secret_post` (FR-C4)
- [ ] UserInfo (FR-C5); `iss` in the authorization response (FR-C14)
- [ ] `apps/server` serves a real OP; `apps/client` completes a login against it

## M2 — storage and conformance

- [ ] `@oidcraft/adapter-drizzle` with migrations and real indexes (FR-A5)
- [ ] `@oidcraft/adapter-kysely`
- [ ] OpenID Foundation conformance suite in CI: `basic`, `config` (NFR-C1)
- [ ] `@oidcraft/node` bridge + a Node smoke test (FR-R3)

## M3 — federation

- [ ] `UpstreamProvider` discovery and the RP leg (FR-F1)
- [ ] Handoff: suspend/resume across the upstream round trip (FR-F3)
- [ ] Home-realm discovery (FR-F4); linking policies (FR-F5)
- [ ] Claim mapping (FR-F7); provenance into the ID token (FR-F6)
- [ ] Logout propagation both ways (FR-F8); `prompt=login` / `max_age` passthrough (FR-F9)
- [ ] Test upstream: a second oidcraft instance (ARCHITECTURE.md §10)

## M4 — the rest of the protocol

- [ ] Revocation, introspection (FR-C8); logout endpoints (FR-C11)
- [ ] PAR, JAR (FR-C12); DPoP (FR-C13)
- [ ] Device grant (FR-C7); DCR (FR-C9); pairwise subjects (FR-C18)
- [ ] Token exchange (FR-C2); RAR (FR-C15); step-up (FR-C16); CIBA (FR-C17)

## M5 — batteries

- [ ] Reference interaction screens (FR-I3), consent memory (FR-I4)
- [ ] Management API (FR-M1) and admin UI (FR-M2)
- [ ] `oidcraft` meta-package; docs site; first manual publish (ARCHITECTURE.md §11)

## Decisions waiting on an answer

`G-1` OpenID Federation 1.0 · `G-2` how much of the account the library owns · `G-3` FAPI 2.0 ·
`G-4` upstream SAML · `G-5` TypeORM · `G-6` multi-tenancy · `G-7` Drizzle v1
