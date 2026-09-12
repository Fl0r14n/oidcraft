# Plan

What is left, in order. `REQUIREMENTS.md` says what it must do, `ARCHITECTURE.md` how.
This file is working state: tick items off and add notes as work lands.

## Status

Scaffold only. The workspace, the toolchain, the build and the adapter contract exist; no protocol
code does. Most entries under `packages/oidcraft/src` are stub barrels proving the wiring, except
`src/adapter.ts` and `src/federation/types.ts`, which are the real contracts everything else is
written against. `bun run --filter=oidcraft build` produces all seven entries and passes
`verify-entries.ts`.

## M0 — foundation

- [x] CI: `biome ci`, build + `verify-entries`, typecheck, `bun test` on push and PR
- [x] `exports.test.ts`: the exports map, the source tree and the build entries agree

- [ ] Root entry: config construction with validation (NFR-D2), route table, error responses
- [ ] `KeyStore` + JWKS endpoint + discovery document (FR-C6, FR-C10)
- [ ] `oidcraft/adapters/memory` and the shared adapter-conformance suite (FR-A3, FR-A4)
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

- [ ] `oidcraft/adapters/drizzle` with migrations and real indexes (FR-A5)
- [ ] `oidcraft/adapters/kysely`
- [ ] OpenID Foundation conformance suite in CI: `basic`, `config` (NFR-C1)
- [ ] `oidcraft/runtimes/node` HTTP bridge + a Node smoke test (FR-R3)
- [ ] Context providers: `oidcraft/runtimes/{bun,deno,workerd}`, one smoke test each (FR-R3, FR-R4)
- [ ] Capability gating: disable mTLS methods where no certificate can be supplied (FR-R5, `G-8`)

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
- [x] First manual publish: `oidcraft@0.0.1` claimed the name — the similarity check cleared
- [ ] `npm trust github` registration, so releases publish from CI (ARCHITECTURE.md §11)
- [ ] Docs site

## Decisions waiting on an answer

`G-1` OpenID Federation 1.0 · `G-2` how much of the account the library owns · `G-3` FAPI 2.0 ·
`G-4` upstream SAML · `G-5` TypeORM · `G-6` multi-tenancy · `G-7` Drizzle v1 ·
`G-8` mTLS on Bun
