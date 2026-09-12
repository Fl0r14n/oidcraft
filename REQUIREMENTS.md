# Requirements

What oidcraft must do. `ARCHITECTURE.md` says how, `PLAN.md` says what is left.

**Requirement ids are stable and are how everything cites everything else.** `FR-*` is a functional
requirement, `NFR-*` a non-functional one, `G-*` an open question with no settled answer. When code,
a commit or the architecture refers to an id, look up the text — never work from a paraphrase.

## 1. Purpose

oidcraft is an OpenID Provider **library**, not a product. It gives a TypeScript application the
authorization-server half of OpenID Connect the way `oidc-provider` does for Node, with three
differences that are the reason it exists:

- **Runtime-portable.** One build runs on Bun, Node, Deno and any workerd-shaped host. The core
  never imports `node:http`, `node:crypto` or any runtime-private API (FR-R1).
- **Batteries included for the interaction half.** `oidc-provider` deliberately refuses to ship
  login, consent or an admin surface; a team therefore writes those before it authenticates
  anybody. oidcraft ships a policy layer and reference screens, closer to what Django's
  oauth-toolkit gives a Django project (FR-I*, FR-M*).
- **Federation is a first-class mode, not an application concern.** An oidcraft deployment can be a
  pure broker in front of Entra, Google or another OP, a local-account OP, or both at once (FR-F*).

### 1.1 Non-goals

- Not an IdP product with its own UI, themes or realm model. It is a library; the screens are
  reference implementations meant to be replaced.
- Not a SAML IdP or SP. Upstream SAML is reachable only through the `UpstreamProvider` extension
  point, never in-tree (G-4).
- Not a user-directory. Accounts, passwords, MFA enrolment and password reset belong to the host
  application behind `AccountStore`. oidcraft authenticates a session; it does not own the user
  (G-2).
- No OpenID4VC / verifiable-credential issuance.

## 2. Actors

| Actor | What it is |
| --- | --- |
| **Host application** | The TypeScript app embedding the library. Owns accounts, storage and deployment. |
| **Relying party (client)** | A registered OAuth client. Confidential, public, or dynamically registered. |
| **End user** | Authenticates at the OP, grants consent. |
| **Upstream provider** | An external OP oidcraft brokers to, where it is itself the relying party. |
| **Resource server** | Validates access tokens, by introspection or by verifying a JWT locally. |
| **Operator** | Runs the deployment; uses the admin surface to manage clients, keys and sessions. |

## 3. Protocol core — `FR-C*`

The core implements the following. Anything not listed is out of scope until it appears here.

**FR-C1 — Authorization endpoint.** `code`, `id_token`, `code id_token` response types.
`response_mode` of `query`, `fragment`, `form_post`. OIDC Core 1.0 §3. Implicit (`token`,
`code token`) is **not** implemented: OAuth 2.1 removes it and RFC 9700 §2.1.2 forbids it.

**FR-C2 — Token endpoint.** `authorization_code`, `refresh_token`, `client_credentials`,
`urn:ietf:params:oauth:grant-type:device_code`, `urn:ietf:params:oauth:grant-type:token-exchange`
(RFC 8693). `password` is **not** implemented, for the same reason as implicit.

**FR-C3 — PKCE (RFC 7636) is mandatory** for every client on the code grant, public or
confidential. `plain` is rejected; only `S256`. A client cannot opt out.

**FR-C4 — Client authentication.** `none`, `client_secret_basic`, `client_secret_post`,
`client_secret_jwt`, `private_key_jwt` (RFC 7523), `tls_client_auth` and
`self_signed_tls_client_auth` (RFC 8705). The mTLS methods require the host to pass the verified
client certificate in; the core never terminates TLS (FR-R4).

**FR-C5 — UserInfo endpoint.** Claims resolved per request through `AccountStore.claims`, never
served from a copy cached at authentication time. Signed and/or encrypted responses when the
client asks for them.

**FR-C6 — Discovery.** `/.well-known/openid-configuration` (OIDC Discovery 1.0), advertising only
what the running configuration actually supports, and `/.well-known/oauth-authorization-server`
(RFC 8414). Protected-resource metadata (RFC 9728) for registered resource servers.

**FR-C7 — Device authorization grant** (RFC 8628), including the user-code interaction screen.

**FR-C8 — Revocation (RFC 7009) and introspection (RFC 7662).** Introspection requires client or
resource-server authentication and returns `active: false` rather than an error for anything the
caller may not see.

**FR-C9 — Dynamic client registration** (OIDC DCR 1.0) with registration access tokens, gated by
an explicit policy: open, software-statement-gated, or disabled. **Disabled is the default.**

**FR-C10 — JWKS endpoint and key rotation.** Multiple active keys; the first signing-capable key
of an algorithm signs, the rest only verify, so a rotation never invalidates live tokens (NFR-S7).

**FR-C11 — Logout.** RP-initiated logout, front-channel logout and back-channel logout. Session
Management 1.0's `check_session_iframe` is **not** implemented — third-party cookie blocking has
made it non-functional in current browsers.

**FR-C12 — Request objects.** JAR (RFC 9101), `request` and `request_uri`. PAR (RFC 9126), with
per-client `require_pushed_authorization_requests`.

**FR-C13 — Sender-constrained tokens.** DPoP (RFC 9449) with nonce support, and mTLS
certificate-bound tokens (RFC 8705 §3).

**FR-C14 — `iss` in the authorization response** (RFC 9207), always, unconditionally.

**FR-C15 — Rich authorization requests** (RFC 9396), with the host supplying the
`authorization_details` type schemas and their consent rendering.

**FR-C16 — Step-up authentication** (RFC 9470): a resource server can demand a higher `acr` or a
fresher `auth_time`, and the OP must honour the resulting `acr_values`/`max_age`.

**FR-C17 — CIBA** — OpenID Connect Client-Initiated Backchannel Authentication, poll and ping
modes. Push mode is out of scope.

**FR-C18 — Pairwise subject identifiers** (`sector_identifier_uri`), alongside public ones.

## 4. Tokens — `FR-T*`

**FR-T1** — ID tokens are always JWS. Default `ES256`; `RS256` supported for legacy clients;
`none` never.

**FR-T2** — Access tokens are opaque by default and JWT (RFC 9068) when a client or resource
server is configured for it. Opaque is the default because a revoked opaque token stops working
immediately and a revoked JWT does not.

**FR-T3** — Refresh tokens rotate on every use. Reuse of a consumed refresh token revokes the
entire grant (RFC 9700 §4.14.2). This is not configurable.

**FR-T4** — Authorization codes are single-use with the same consequence on replay: consuming a
code twice revokes the grant it belongs to.

**FR-T5** — Every artifact carries an absolute expiry that storage enforces, so a store that
misses a prune cycle still cannot serve an expired token.

## 5. Storage — `FR-A*`

**FR-A1** — Storage is reached only through the `Adapter` capability interfaces
(`ARCHITECTURE.md` §4). The core performs no I/O of its own and holds no in-process state that
survives a request, so two processes behind a load balancer behave identically to one.

**FR-A2** — An adapter is a set of narrow, typed stores (`ClientStore`, `ArtifactStore`,
`SessionStore`, `GrantStore`, `AccountStore`, `KeyStore`, `ReplayGuard`, and optionally
`FederatedIdentityStore`) — not one stringly-typed blob table keyed by model name.

**FR-A3** — A `KvStore` implementation (`get`/`set`/`delete`/`scan`) is sufficient to derive a
complete `Adapter`, so a new backend is a day's work rather than a week's.

**FR-A4** — First-party adapters ship for **Drizzle** (Postgres and SQLite) and **Kysely**
(Postgres, SQLite, MySQL), plus an in-memory one for tests. Each ships its schema as migrations
the host runs, never as something the library applies at boot.

**FR-A5** — Adapters that own their schema must expose real columns and indexes for every value
the core queries by (`grant_id`, `user_code`, `expires_at`, `account_id`, upstream session id). A
JSON blob with no index is a correctness problem at revocation time, not just a slow one.

**FR-A6** — A TypeORM adapter is community-supported, not first-party (`G-5`). A third-party adapter
is an ordinary package depending on `oidcraft` and implementing `Adapter`; nothing about the
contract is internal.

## 6. Federation — `FR-F*`

Two different things are called federation, and oidcraft means the first:

- **Identity brokering** (this section): oidcraft is the OP its clients see, and simultaneously a
  relying party at one or more upstream OPs. Downstream clients never learn the upstream exists.
- **OpenID Federation 1.0** — entity statements, trust chains, trust anchors, automatic
  registration across a multilateral trust fabric. A different protocol, deferred (`G-1`).

**FR-F1 — Upstream providers are configuration, not code.** An upstream is an issuer URL, client
credentials, scopes and an optional claim mapper. Discovery resolves its endpoints. Google, Entra
and Keycloak are examples of the same generic path, not special cases.

**FR-F2 — Brokering mode is per-deployment and per-client.** A deployment may hold local accounts
only, broker only (no local credentials at all), or both. A client may be restricted to a subset
of upstreams (`Client.upstreamProviders`).

**FR-F3 — The upstream round trip suspends and resumes one interaction.** The handoff carries
`state`, `nonce`, the PKCE verifier and the id of the downstream interaction it resumes. It is
single-use, expires, and is bound to the browser it started in.

**FR-F4 — Home-realm discovery.** Which upstream to use is chosen from `login_hint`, the email
domain, `acr_values`, the client's allowed list, or by asking the user — in that order, each step
skippable by configuration.

**FR-F5 — Account linking is by `(provider, subject)` and nothing else, by default.** Other
policies (`verified-email`, `interactive`) exist and must be chosen deliberately, because they
are the difference between a safe broker and an account-takeover primitive (NFR-S8).

**FR-F6 — Provenance reaches the ID token.** A brokered session records the upstream that
authenticated it, and the `idp`, `acr`, `amr` and `auth_time` claims reflect the upstream's
answer rather than being invented locally.

**FR-F7 — Claim mapping is explicit.** Nothing from an upstream becomes a local claim without a
mapper saying so. `sub` is never taken from anywhere but the upstream `sub`.

**FR-F8 — Logout propagates in both directions.** An upstream back-channel logout terminates the
local sessions it produced, which in turn triggers this OP's own back-channel logout to its
clients. RP-initiated logout optionally propagates upward.

**FR-F9 — Re-authentication passes through.** `prompt=login`, `max_age` and a raised `acr_values`
force a fresh upstream authentication rather than being satisfied by the local session.

**FR-F10 — Upstream tokens are not retained by default.** Retaining them turns the deployment into
a credential store for another system; it must be opted into per provider, and the tokens must be
reachable only through an explicit, audited API (NFR-S9).

**FR-F11 — An upstream failure is an OAuth error, not a stack trace.** A dead or misbehaving
upstream produces a well-formed error response to the downstream client and a logged diagnostic.

## 7. Interaction — `FR-I*`

**FR-I1** — When the authorization endpoint cannot decide alone, it produces an
`InteractionRequest` and redirects to the interaction app. The core never renders HTML.

**FR-I2** — The interaction app answers with an `InteractionResult`; the core re-evaluates the
original authorization request against it and is free to demand another interaction.

**FR-I3** — Reference screens ship for login, consent, account selection, upstream selection,
device-code entry and logout confirmation, as Vue SFCs a host can replace wholesale.

**FR-I4** — Consent is remembered as a durable `Grant`, so a returning user is not asked again for
scopes already granted, and revoking the grant re-asks.

**FR-I5** — `prompt=none`, `prompt=login`, `prompt=consent`, `prompt=select_account` are all
honoured, including the error responses when `none` cannot be satisfied.

**FR-I6** — `ui_locales` selects the screen language; the reference screens ship English and are
structured for translation.

## 8. Administration — `FR-M*`

**FR-M1** — A management API over clients, grants, sessions, keys and upstream providers, exposed
as fetch handlers the host mounts behind its own authentication. **The library never decides who
is an administrator.**

**FR-M2** — A reference admin UI covering client CRUD, key rotation, upstream configuration,
session inspection and grant revocation.

**FR-M3** — Every write through the management API emits an audit event. The host decides where
audit events go; the library does not persist them.

## 9. Runtime — `FR-R*`

**FR-R1** — The core's only inputs are a WHATWG `Request` and configuration; its only output is a
`Response`. No `node:*` import anywhere in its graph.

**FR-R2** — All cryptography goes through WebCrypto (`crypto.subtle`, `crypto.getRandomValues`)
via `jose`. No `node:crypto`, no native addon, no dependency on a C++ build.

**FR-R3** — Supported hosts: Bun ≥ 1.4, Node ≥ 22 (via the `oidcraft/node` entry), Deno, and workerd-shaped
runtimes. A host bridge may exist only to translate the runtime's HTTP types to `Request`/
`Response`; it may never contain protocol logic.

**FR-R4** — Everything the core cannot learn from the `Request` — the client TLS certificate, the
real client IP, the deployment's public origin — is passed in explicitly. The core never reads
`X-Forwarded-*` on its own authority (NFR-S6).

## 10. Non-functional

### Security — `NFR-S*`

**NFR-S1** — RFC 9700 (BCP 240) is the baseline, not a later hardening pass. Where it and OIDC
Core disagree, RFC 9700 wins and the deviation is documented here.

**NFR-S2** — Redirect URIs match exactly. No wildcards, no prefix matching, no `localhost` port
exception in production configuration.

**NFR-S3** — Every token, code and identifier is generated with `crypto.getRandomValues` at ≥ 256
bits of entropy and compared in constant time where compared at all.

**NFR-S4** — Replay of a single-use artifact revokes its grant (FR-T3, FR-T4).

**NFR-S5** — `jti`, DPoP proofs and upstream nonces are checked against `ReplayGuard` within their
validity window.

**NFR-S6** — The issuer identifier is configuration. It is never derived from the `Host` or
`X-Forwarded-Host` header, which would let a request rewrite the issuer of the tokens it receives.

**NFR-S7** — Key rotation never invalidates a live token: verification keys outlive the signing
key by at least the longest token TTL.

**NFR-S8** — No implicit account linking on an unverified email address. The default linking
policy matches on `(provider, subject)` only.

**NFR-S9** — Upstream access and refresh tokens are stored only when a provider opts in, are
encrypted at rest by the adapter, and are never returned to a downstream client by default.

**NFR-S10** — No secret is ever logged. Tokens appear in logs as a prefix and a hash, if at all.

### Conformance — `NFR-C*`

**NFR-C1** — The OpenID Foundation conformance suite runs in CI against the reference deployment,
for the `basic`, `config` and `dynamic` OP profiles. A red suite is a failed build.

**NFR-C2** — FAPI 2.0 Security Profile is a target for a later milestone, not for 1.0 (`G-3`).

**NFR-C3** — Every `FR-C*` requirement has at least one test that exercises the wire format, not
just the internal function.

### Performance — `NFR-P*`

**NFR-P1** — A token-endpoint call performs at most two storage round trips.

**NFR-P2** — Discovery and JWKS responses are cacheable and served without a storage read on the
hot path.

**NFR-P3** — Expired-artifact pruning is a bounded sweep the host schedules. The library starts no
timers and no background tasks of its own.

### Developer experience — `NFR-D*`

**NFR-D1** — A working OP, in memory, in under 30 lines and with no database.

**NFR-D2** — Configuration is type-checked. An unsupported combination — an advertised algorithm
with no key, DPoP required with no nonce store — fails at construction, not at the first request.

**NFR-D3** — Errors carry the OAuth error code, the specification clause and what the caller must
change.

**NFR-D4** — Zero runtime dependencies beyond `jose`. Everything else — `openid-client`,
`drizzle-orm`, `kysely` — is an optional peer confined to its own subpath entry, so importing the
core pulls none of them.

## 11. Open questions — `G-*`

**G-1 — OpenID Federation 1.0.** Real trust-chain federation is a large, separate protocol. Ship
brokering (FR-F*) first; decide later whether entity statements are in scope at all.

**G-2 — How much of the account does the library own?** `AccountStore` currently pushes passwords,
MFA and enrolment entirely onto the host, which makes "batteries included" thinner than Django's
oauth-toolkit. An optional `oidcraft/accounts` entry with argon2 and TOTP would close the gap and widen
the security surface.

**G-3 — FAPI 2.0.** Worth the constraint it imposes on the core's defaults, or a profile package?

**G-4 — Upstream SAML.** The `UpstreamProvider` interface could accommodate it. Whether anyone
should is a different question.

**G-5 — TypeORM.** At 3.6M weekly downloads against Drizzle's 16.5M it is no longer where the
ecosystem is. First-party, community, or not at all?

**G-6 — Multi-tenancy.** One process serving several issuers is a different configuration and
storage shape. Deferred, but the adapter interfaces should not make it impossible.

**G-7 — Drizzle v1.** `drizzle-orm` is at `1.0.0-rc.5` with `latest` still on `0.45.2`. The
adapter targets `0.45` until v1 is on `latest`.
