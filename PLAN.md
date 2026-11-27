# Plan

What is left, in order. `REQUIREMENTS.md` says what it must do, `ARCHITECTURE.md` how.
This file is working state: tick items off and add notes as work lands. Git history holds what
was done.

## Status

**Implemented, as of 2026-11-27**, with 2301 passing tests against Postgres, MySQL, MariaDB and Redis,
`bun run verify` as the gate, and `bun run smoke` and six OpenID Foundation plans in CI: every
functional requirement in `REQUIREMENTS.md`.
`metadata.test.ts` exercises every advertised discovery value rather than reading it. Published as
`@oidcraft/*`, each from a GitHub release with provenance; on 2026-11-27, after the 2026-11-26 review,
`core` 0.6.0, `client` 0.5.0, `adapter` 0.4.0, the provider 0.10.0, the four storage adapters 0.4.0,
`vue` 11.0.0, `react` 6.0.0 and `angular` 13.0.0, then `core` 0.6.1, `adapter` 0.4.1 and the provider 0.10.1 —
with the docs site at https://fl0r14n.github.io/oidcraft/.
Each release's notes, what to change when upgrading included, are on its GitHub release.

**Provider 0.3.0 and earlier are not to be put in front of real identities**: they ship a session
takeover through `sid` and the other security faults fixed in 0.4.0.

The authorization code grant with mandatory PKCE, interaction suspend/resume, token issuance with
rotation and replay revocation, UserInfo, revocation, introspection, logout in both directions,
DPoP with nonces, PAR, JAR by value, the `claims` parameter, dynamic client registration with RFC
7592 management, the device grant, CIBA in poll and ping, token exchange, RAR, step-up, pairwise
subjects, identity brokering with home-realm discovery chosen by the provider, five storage adapters
(memory, Drizzle, Kysely, TypeORM, Redis) passing one conformance suite, the SQL ones on SQLite,
Postgres, MySQL and MariaDB, four runtime context providers and a Fastify plugin, local accounts with passwords, passkeys,
TOTP and email sign-in (FR-I9), a management API and an admin UI, and identity assertion grants for MCP's
enterprise-managed authorization (FR-C24).

### What is NOT done, and will not be silently forgotten

**The OpenID Foundation suite's `basic`, `config` and FAPI 2.0 plans gate CI** (NFR-C1), with the
refusals `conformance/README.md` lists. That is a passing run, not certification: three `basic`
modules and five FAPI ones end in REVIEW, which a person signs off with screenshots only when
certifying. Each was pre-checked from its page source on 2026-11-13 and shows the page its module
asks for.

**One deployment runs it in production and another in staging**, each serving its own web application
through the bindings here, one brokering to upstreams and the other serving MCP clients through
metadata documents. Nothing has run it under measured load. Implemented is not certified: beyond what
those two exercise, no `FR-*` has been checked by anything but its author and its tests.

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
- **Removing every passkey on a passkey recovery** — FR-I8 ends the sessions and tokens the lost one
  opened, not the passkey: only its owner knows which one is gone, and the others are not lost. The
  screens after a recovery say to remove it.
- **Renaming the demo's `/federation/callback`** — it is the redirect URI registered with Google
  (`.env.example`), and renaming a URL people have registered breaks their sign-in for a word.

## Open

- **`completeHere` from another browser refuses a device interaction** by construction, as a device
  one carries no stored request (FR-I9); no test drives one.

- **Brave's own password manager** refused a passkey under `localhost`, through a phone by QR code, and
  was not retried under another name, as Proton Pass was (`.cert/README.md`). Google Password Manager
  and Proton Pass pass end to end.
- **What FR-C24 leaves out, on purpose until a deployment needs it:** an assertion bound by `cnf`
  (draft §9.11, and its `jwt-dpop` grant type) is refused rather than checked; Claude's own beta
  assertions, whose `sub` is opaque, are not accepted, since only an email would find their account;
  and with no `Grant` recorded, a password reset or `grants.revoke` does not reach the tokens, which
  live at most the access-token lifetime — `artifacts.destroyByAccountId` would close that.

## Review of 2026-11-26

A requirements and code review at `3f28d2e`, worked through section by section. Nothing critical; `[test]`
marks a finding reproduced by a throwaway test. Paths are under `packages/provider/src/` unless they say otherwise.

### 1. Requirements

- [x] FR-C4: a client assertion's `aud` is the issuer, sole value (RFC 10070, Nov 2026). Code: S-2.
- [x] FR-C21: FAPI 2.0 §5.3.2.1 bounds `iat`/`nbf` in the _future_ (accept ≤ 10 s, reject > 60 s); the text and
      `clients/assertion.ts:57` read it as "`nbf` at most 60 s old". Add `redirect_uri` required in PAR (§5.3.2.2)
      and RSA ≥ 2048 / EC ≥ 224 (§5.4.1). The bound landed with S-2; `redirect_uri` is required of every request, and
      jose refuses an RSA key under 2048 bits for any RS or PS algorithm, ES256 being P-256 alone. `fapi.test.ts` pins
      all three.
- [x] NFR-S1: OAuth 2.1 is at -17 (§7.5.1.1 unchanged).
- [x] FR-I7, G-9: NIST SP 800-63B rev 4 (§3.2.2 rate limiting); FR-I7 has no password policy (length, blocklist).
- [x] FR-L4: RFC 10017 / BCP 212 on `localStorage` and BFF.
- [x] FR-C20: CIMD -03 §10.7 (no fetch of special-use addresses) normative.
- [x] §1 "batteries included" vs `@oidcraft/ui` private; FR-C19 vs code on the owning client introspecting; ID token
      encryption unstated; FR-C19 multi-resource authorization unstated; G-\* titled open but decided; FR-L\* and the
      password grant in `oauthForm()`.
- [x] Missing: OP session lifecycle (re-login, idle, cookie prefix); clickjacking (RFC 9700 §4.16); SSRF on
      client-chosen URLs; host delivers back-channel logout and CIBA pings; token exchange policy;
      client_credentials; sender-constraint fails closed; DCR (initial access token, https for web, RFC 7592 update
      keeping operator fields); local vs brokered account-id namespace; what a reset voids; account suspension;
      payload evolution across upgrades; request object `exp`; `prompt=create`.
- [x] NFR-C1: RP-Initiated Logout, Back-/Front-Channel Logout and Form Post OP plans are not run.
- [x] Sub-ids for FR-C20, FR-C22, FR-C24, FR-I9. `FR-C24.1` names one rule of a long requirement; the docs site
      anchors each and counts a citation of it for its parent too. Code citing one rule cites its sub-id.

### 2. Architecture

- [x] A1 store wrappers spread (`artifacts.ts:23`, `clients/metadata-document.ts:81`, `keys/signer.ts:25`): a
      class-based adapter loses prototype methods inside the provider.
- [x] A2 artifact payloads unversioned and cast (`payloads.ts`); e.g. `token/code.ts:141` on a pre-`familyExpiresAt` token.
- [x] A3 host obligations with no reference implementation: SSRF-safe fetch, mail delivery, security headers,
      DPoP-aware resource check. `provider.verifyAccessToken` and each runtime's `safeFetch` landed; mail and headers are
      demo items (D-3, D-7).
- [x] A4 invariants at call sites: family liveness (`issueAccessToken`), consent rule twice, sender-constraint
      matching ×3, token visibility ×4, cookies ×3, error factories. The cookies landed with S-10 (step 4);
      `outstandingConsent`/`assertConsentCovers`, `assertAccessToken` and its `refused`, `StoredId`.
- [x] A5 `authorize ↔ token ↔ clients` import cycle; authorization endpoint inside `provider.ts`.
- [x] A6 throttling on `ReplayGuard` slots → an atomic counter on the adapter.
- [x] A7 whole-row credential writes → field merge or CAS. The contract has `update`; the provider moves onto it in step 4 (A-6, S-1).
- [x] A8 Redis single `~keys` set; no injectable clock. The README says so.

### 3. Structure

- [x] One SQL kernel in `@oidcraft/sql` for drizzle/kysely/typeorm.
- [x] Split `authorize/authorization.ts`, `clients/registration.ts`, refresh paths in
      `token/code.ts`. `accounts/index.ts` and the demo's `interaction/routes.ts` are split. Done 2026-11-27, no
      behaviour change: `authorize/request.ts` parses and validates, `authorize/response.ts` delivers every response,
      `authorization.ts` decides; `redirectMatches` is in `clients/uris.ts` and `detailsConsentId` in `consent.ts`;
      `clients/metadata.ts` reads a client's metadata in and out for registration and metadata documents alike;
      `token/refresh.ts` and `token/replay.ts` beside `token/code.ts`.
- [x] `broker.complete` verifies twice; `sealed.ts` has no key id (done: HKDF and a key id, `v1` still read).
      `completeAuthorization` answers the claims it verified, and the broker takes them.

### 4. Security

Medium:

- [x] S-1 `[test]` a login never ends the browser's previous session (`authorize/interactions.ts:193`, `session/session.ts:37`).
- [x] S-2 `[test]` assertion `aud` accepts the token endpoint and arrays (`clients/assertion.ts:23`).
- [x] S-3 `[test]` introspection accepts a `none` client; RFC 7592 update keeps operator fields (`resource/introspection.ts:45`, `clients/registration.ts:401`).
- [x] S-4 `[test]` cert-bound client without a certificate gets bearer tokens; `dpopBoundAccessTokens` ignored with DPoP off (`token/endpoint.ts:22,59`).
- [x] A-1 `[test]` account-wide lockout renews the generation, freeing every slot (`accounts/index.ts:264,302`).
- [x] A-2 `allowedUpstreams` not enforced at `interactions.complete` (`authorize/interactions.ts:292`).
- [x] R-1 `fromKv` `destroyByClientId` scans, reachable from RFC 7592 DELETE (`packages/adapter/src/kv.ts:156,303`).
- [x] R-2 ID token `iss` unchecked without a configured issuer (`packages/core/src/jwt.ts:170`).
- [x] R-3 `@oidcraft/client` uses a server-side process-wide `localStorage` (`packages/client/src/storage.ts:5`).

Low:

- [x] S-5 `[test]` `sector_identifier_uri` skips `serverUri` (`clients/registration.ts:89`).
- [x] S-6 `issueAccessToken` skips family/client liveness (exchange, client credentials, ID-JAG).
- [x] S-7 `[test]` session lists the client before consent → logout token to a refused client (`session/session.ts:48`).
- [x] S-8 introspection `token_type` DPoP for an mTLS-bound token (`resource/introspection.ts:27`).
- [x] S-9 PKCE nonce exemption under FAPI (`authorize/pkce.ts:13`).
- [x] S-10 `oidcraft.sid` without `__Host-` (`session/session.ts:7`).
- [x] S-11 request object without `exp`/`jti`/max lifetime (`authorize/request-object.ts:21`).
- [x] S-12 exchange: another client's refresh token as subject; actor `cnf`; scopes not ⊆ client's (`token/exchange.ts`).
- [x] S-13 DPoP errors 400 at UserInfo, not 401 + `WWW-Authenticate` (`binding/dpop.ts:34`).
- [x] S-14 array claims in a request object stringified (`authorize/request-object.ts:50`).
- [x] S-15 web clients may register custom-scheme / `http://127.0.0.1` redirects (`clients/registration.ts:39`).
- [x] S-16 CIBA `id_token_hint` unverified (`authorize/ciba.ts:105`).
- [x] S-17 device endpoint accepts scopes approval can never grant (`authorize/device.ts:43`).
- [x] S-18 `.catch(() => undefined)` hides storage failures (`provider.ts:168`).
- [x] S-20 discovery advertises front- and back-channel logout unconditionally (`discovery.ts:85-96`), with no
      `onLogout`/`onFrontChannelLogout` to deliver them (FR-C6); the demo sets neither.
- [x] A-3 `UpstreamProvider.linkPolicy` never read (`broker/types.ts:207`).
- [x] A-4 reset by passkey keeps the password (`accounts/index.ts:721`).
- [x] A-5 reset leaves other reset/email tokens live (`accounts/index.ts:376`).
- [x] A-6 credential writes undo each other (`accounts/index.ts:475,562-609`).
- [x] A-7 brokered login without upstream `auth_time` stamped now (`session/session.ts:43`).
- [x] A-8 known/unknown username timing via slot probing (`accounts/index.ts:275`).
- [x] A-9 `setPassword` clears a host-set `lockedUntil` (`accounts/index.ts:474`).
- [x] A-10 claim-mapping doc vs default mapper (`broker/types.ts:201`).
- [x] R-4 `oauthFetch(Request)` drops its headers (`packages/client/src/fetch.ts:20`).
- [x] R-5 refresh lock released mid-request (`packages/client/src/token.ts:192`).
- [x] R-6 ID token without `exp`/`iat` accepted; no `algorithms` (`packages/core/src/jwt.ts:176`).
- [x] R-7 whitespace-prefixed `http` passes `assertSecure` (`packages/core/src/secure.ts:90`).
- [x] R-8 `grants.upsert` unions in `fromKv`, overwrites in SQL.
- [x] R-9 state-less error callback consumes the pending sign-in (`packages/client/src/flows.ts:174`).

Hardening, all done but the per-upstream callback path, decided against: security headers on HTML (D-7, NFR-S13);
device user-code limits (global cap, /64, modulo bias); password and body length caps (128 characters, 1 MiB);
`cf-connecting-ip` and proxy options per runtime (`trustProxy` on Node, Bun and Deno); realm key check by thumbprint;
RFC 8265 usernames; client-assertion `jti` namespaced by client; PKCE value formats; `request_uri` without `client_id`;
MySQL PAD SPACE collations (in `0001_init`); email cap per normalised address.

Reference deployment (`apps/demo-server/src`):

- [x] D-1 high `[test]` username as account id collides with `google:<sub>` (`op/accounts.ts:28`, `interaction/broker.ts:38`).
- [x] D-2 high demo accounts and admin seeded in production (`op/provider.ts:29`, `.env.example`).
- [x] D-3 reset and email links printed to stdout in production (`op/accounts.ts:103`).
- [x] D-4 TOTP enrolment needs only the bearer token (`account/api.ts:130`).
- [x] D-5 realm private keys written 0644 (`op/realms.ts:41`).
- [x] D-6 MCP metadata resolver: SSRF, unbounded body (`mcp/server.ts:46`).
- [x] D-7 no CSP / `frame-ancestors` on the screens (`packages/ui/src/render.ts:38`).
- [x] D-8 resource checks accept DPoP-bound tokens as bearer (`op/first-party.ts:284`, `mcp/server.ts:71`).
- [x] D-9 `/authorize` error page echoes the client id (`index.ts:75`).
- [x] D-10 FAPI demo state unbounded and unbound (`fapi/demo.ts:68`).

### Decided while working through section 1

- Q1 FR-C4: assertion `aud` is the issuer only (string or one-element array), no compatibility setting.
- Q2 FR-I7: NIST rev 4; `minPasswordLength` defaults to 15, configurable; the 128 maximum also enforced at sign-in
  after the decoy hash; a `rejectPassword` hook for a blocklist.
- Q3 FR-L4: name BCP 212 and what oidcraft meets of it. Planned: DPoP in `@oidcraft/client` with a non-extractable key.
- Q4 §1 Purpose: the screens are a reference deployment to copy, not a library feature. `@oidcraft/ui` stays private.
- Q5 FR-C19: the owning client may introspect its token. FR-T1: ID token encryption (optional in OIDC Core §2) not implemented.
- Q6 token exchange FR: refresh tokens only from their own client; bound tokens need their proof; scopes ⊆ subject ∩
  client ∩ policy; `act`, revoked with the subject's family; `exchangePolicy` stays the gate.
- Q7 FR-C12: request objects need `exp`, live ≤ 60 min; future `iat`/`nbf` refused; no `jti` tracking; `typ` checked if present.
- Q8 session lifecycle: same account signing in again updates the session in place; another account ends the old
  session fully first; optional `ttl.sessionIdle`, off. Its "no cookie rotation" was reversed on 2026-11-27: the
  cookie is `<id>.<secret>` and every sign-in replaces the secret (step 8 below).
- Q9 account ids: one id names one account; sign-up refuses an id with linked identities, `linkIdentity` one with a
  credential or passkey; JSDoc on `newAccountId`; the demo uses random ids.
- Q10 resets: a completed reset voids every other reset and email sign-in token (per-account counter); a reset
  finished with a passkey removes the password. The host's suspension (`lockedUntil`, now `lock`) is honoured,
  never cleared, not lifted by a reset (throttling locks still are).
- Q11 NFR-C1: fix S-20, the demo delivers both logouts, then Form Post and the three logout OP plans run as parallel
  CI jobs; REVIEW modules are acceptable while nothing fails.
- Q12 sub-ids for FR-C20, FR-C22, FR-C24, FR-I9: later, on their own.
- Written into REQUIREMENTS.md without a question of their own: FR-C8 (a public `client_id` is not
  authentication), FR-C9 (initial access tokens, https for web, an RFC 7592 auth-method change drops operator
  fields), FR-C11/FR-C17 (the host delivers; advertised only with the hook), FR-C13 (fails closed), FR-C26
  (client credentials), FR-I10 (session), NFR-S13 (framing), NFR-S14 (client-chosen URLs), NFR-D6 (payloads).

### Decided in section 2

Implementation waits for every section's decisions; refactoring lands as part of the fix it motivates.

- A1 `toPlainAdapter` in `@oidcraft/adapter` (`src/plain.ts`, per store `toPlainStore`): every store as a plain object
  of its own and inherited methods, bound to the original. `createProvider`, `createRealms`, `createAccounts` and
  `createBroker` normalise on entry; `resolveConfig` checks required methods after; the conformance suite also runs
  against the normalised adapter. Ships in one adapter release with A7.
- A2 light: a refresh token without `familyExpiresAt` is refused; ARCHITECTURE §9 gains "a field that restricts a
  stored artifact is checked as present where it is read: absent is refused, never unrestricted"; NFR-D6 softened to
  that rule. No version stamps or decoders.
- A3 the library ships two things: `safeFetch` in each runtime entry (seeded from reghedge's `client-metadata.ts`;
  Node pins the address, a runtime that cannot pins nothing and says so, workerd caps size and time), and
  `provider.verifyAccessToken(request, { resource })` lifted from UserInfo, answering a ready 401 (fixes S-13, D-8).
  Mail delivery and security headers are demo items.
- A4 each rule moves into the one function every path passes through, as the fix for its finding: family and client
  liveness into `issueAccessToken` (S-6), `assertBoundTo`, one token-visibility module (S-3, S-8), one
  `assertConsentCovers`, one cookie module (S-10), one set of error builders (S-13), a branded `StoredId`.
- A5 the authorization handler moves from `provider.ts` to `authorize/endpoint.ts`. The `authorize ↔ token ↔ clients`
  cycle stays: feature grouping is preferred.
- A6 no counter primitive: keep the generation when the account-wide lock trips (A-1); unknown usernames get a
  symmetric bucket keyed by the normalised username (A-8).
- A7 `UpdatableStore<T, Key>` = `EntityStore<T>` + `update(id, fields) → boolean`, writing only the fields given and
  never creating: `SessionStore` (key `id`; FR-I10's in-place update must not race `addClient`), `CredentialStore`
  (`accountId`, `username`), `PasskeyStore` (`accountId`, `credentialId`). §9.3 gains the verb; three conformance
  checks. Fix ARCHITECTURE §4's stale `ClientStore` row.
- A8 the Redis README says it expects one node or one hash slot; the per-family split waits for a Cluster user. No
  injectable clock.

### Decided in section 3

- One SQL core in private `@oidcraft/sql` over six primitives per ORM (`one`, `many`, `insertIgnore`, `update`,
  `delete`, `upsert`); drizzle, kysely and typeorm keep only driver-result normalisation and table definitions. Before
  A7, so `update` is written once; R-8 settles on overwrite.
- File splits land with the fix that touches them: `accounts/index.ts` (throttle, recovery, reset, email sign-in, TOTP
  enrolment), `authorize/authorization.ts` (`response.ts`, consent check, one interaction `kind`), `clients/uris.ts`,
  the two refresh paths in `token/code.ts`, the demo's `interaction/routes.ts` by flow.
- `broker.complete` verifies once. `sealed.ts` derives its keys with HKDF and carries a key id, reading the old format.

### Decided in section 4

- Settled by sections 1–3: S-1, S-2, S-3, S-4, S-5, S-6, S-9, S-11, S-12, S-13, S-15, S-19, S-20, A-1, A-4, A-5, A-6,
  A-8, A-9, R-8, D-1.
- S-7 a session starts with no clients, a client is added when it gets tokens. S-8 `DPoP` only for a `jkt`. S-14
  array claims as repeated parameters. S-16 the CIBA hint verified as end-session's is. S-17 `openid` and known scopes
  at the device endpoint. S-18 catch only `OAuthError`. A-2 `complete` refuses an idp outside `allowedUpstreams`. A-3
  each upstream's `linkPolicy` honoured, the stricter wins. A-10 the doc follows the default mapper. R-2 `strict`
  refuses to verify without an issuer. R-3 storage only in a browser. R-4, R-5, R-6, R-7, R-9 as found.
- Hardening: all of it except a per-upstream callback path, which would change the URIs registered at the upstreams.
- S-15 a registration that omits `application_type` and uses only loopback or app-scheme redirects is `native`;
  one mixing them with https is refused, as is an explicit `web` client using them.
- S-10 a clean break to `__Host-oidcraft.sid`: one sign-in at the provider after upgrading, in the release notes.
- A-7 a fresh login required downstream sends `prompt=login` upstream, and a missing upstream `auth_time` is the
  moment the round trip started.
- R-1 the per-client index without a fallback scan; artifacts older than it outlive a deleted client until they
  expire, in the release notes.
- Demo: D-2 seeding only with `OIDCRAFT_DEMO_ACCOUNTS=on`, no default password, admins by username; D-3 console mail
  only outside production; D-4 TOTP enrolment needs the password or a passkey; D-5 `0600`/`0700`; D-6 `safeFetch`;
  D-7 headers in `render()`; D-8 `verifyAccessToken`; D-9 the error code only; D-10 state bound to a cookie, with a TTL.

### Order of work

Each step ends green on `bun run verify` and is committed on `main`; a release is the user's to cut.

1. **Provider, no contract change.** S-2, S-3, S-4, S-5 with NFR-S14 and `clients/uris.ts`, S-6 and the rest of A4,
   S-7, S-8, S-9, S-11 to S-20, A-2, A-3, A-10, A2, A5, `verifyAccessToken`. Accounts: A-1, A-8, A-4, A-5, A-9, the
   password policy, the account-id checks (Q9), splitting `accounts/index.ts` as it goes.
2. **Relying-party libraries.** R-2 to R-7, R-9 in `@oidcraft/core` and `@oidcraft/client`.
3. **Storage.** The SQL core; then A1 `toPlainAdapter`, A7 `UpdatableStore`, R-1, the MySQL collations, the Redis
   README. One `@oidcraft/adapter` release and the four adapters.
4. **Provider on the new contract.** S-1 and FR-I10 with `ttl.sessionIdle`, S-10, A-6, A-7, `sealed.ts`, `safeFetch`.
5. **Demo and conformance.** D-1 to D-10, delivering both logouts, the four plans in CI, splitting `routes.ts`.
6. **Hardening** not already landed with its neighbour.
7. **One time vocabulary** (done 2026-11-27, rides in the `core`, `adapter` and `client` releases). Every instant is
   `EpochMillis` in `@oidcraft/core`'s `Created`/`Timestamped`/`Expiring`/`Used`; `Date` is gone from records,
   payloads and results. Renamed: Handoff `startedAt` → `createdAt`, device `lastPolledAt` → `lastUsedAt`,
   refresh `familyExpiresAt` (seconds) → `family.expiresAt`, `Credential.lockedUntil` → `lock.expiresAt`, a
   `locked` refusal's `until` → `lock`, `OAuthToken.expires` → `expiresAt`. Read once in the old shape: a stored
   browser token's `expires`, a refresh token's `familyExpiresAt` (drop after 90 days), a throttle's `lockedUntil`.
   No column changed. Before upgrading `@oidcraft/client`, a host that forces expiry with `expires` must write
   `expiresAt`: the index signature on `OAuthToken` hides it from the compiler.
8. **Review of everything since provider 0.9.0** (2026-11-27). Fixed: a KV store 0.3 wrote is read with its ISO
   instants and `lockedUntil`, so a deploy lifts no suspension; a KV session's clients live as long as it does; Drizzle
   on better-sqlite3 runs writes with `run`; the demo delivers front-channel logout from any request that ends a
   session. Decided: the session cookie is `<id>.<secret>` with `secretHash` stored (`0008_session_secret`), a new
   secret at every sign-in and the `sid` kept (NFR-S11, FR-I10), where a cookie from before still opens its session
   until then; the device flow's wrong-code limits are `userCodeAttempts`, the global one documented as spendable.
   Kept: `http://localhost` alone does not make a registration native (S-15, RFC 8252 §8.3).
9. **`fromKv` lists an account's linked identities by an index** (NFR-P1), as every sign-up does through
   `linkedElsewhere`; it scanned every identity. Ones written before it are indexed once, by the first listing.

### Future features

- A per-client "end other sign-ins" primitive and an `onSessionStart` event, for a host limiting sign-ins per
  account and client (one web, one MCP).

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

**`@oidcraft/ui/bun-plugin` patches `@vuetify/v0`** for its import cycle under Bun's dev bundler. Drop
it when upstream stops needing it; if it breaks again, Reka UI for the dialog and TanStack Table for
the table are the replacements considered.

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
