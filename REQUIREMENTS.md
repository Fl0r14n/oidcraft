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
- Not a user-directory by default. Accounts belong to the host application behind `AccountStore`;
  `oidcraft/accounts` is an optional implementation of it, not a requirement to use one (FR-I7).
- No OpenID4VC / verifiable-credential issuance.

## 2. Actors

| Actor                      | What it is                                                                        |
| -------------------------- | --------------------------------------------------------------------------------- |
| **Host application**       | The TypeScript app embedding the library. Owns accounts, storage and deployment.  |
| **Relying party (client)** | A registered OAuth client. Confidential, public, or dynamically registered.       |
| **End user**               | Authenticates at the OP, grants consent.                                          |
| **Upstream provider**      | An external OP oidcraft brokers to, where it is itself the relying party.         |
| **Resource server**        | Validates access tokens, by introspection or by verifying a JWT locally.          |
| **Operator**               | Runs the deployment; uses the admin surface to manage clients, keys and sessions. |

## 3. Protocol core — `FR-C*`

The core implements the following. Anything not listed is out of scope until it appears here.

**FR-C1 — Authorization endpoint.** The `code` response type only. `response_mode` of `query`,
`fragment`, `form_post`.

Implicit (`token`, `id_token`, `id_token token`) and hybrid (`code token`, `code id_token`,
`code id_token token`) are **not** implemented and are not advertised: OAuth 2.1 removes them,
RFC 9700 §2.1.2 says clients SHOULD NOT use the token-bearing ones, and anything returning an ID
token through the front channel hands it to the browser's history and `Referer`. The cost is that
oidcraft is not a Dynamic OpenID Provider in the sense of OIDC Core §15.2, which must support
`id_token` and `id_token token` (NFR-C1). This was listed as supported for a while and advertised in discovery while the code
refused it — see `metadata.test.ts`, which now tries every advertised value rather than reading it.

**FR-C2 — Token endpoint.** `authorization_code`, `refresh_token`, `client_credentials`,
`urn:ietf:params:oauth:grant-type:device_code`, `urn:ietf:params:oauth:grant-type:token-exchange`
(RFC 8693). `password` is **not** implemented, for the same reason as implicit.

**FR-C3 — PKCE (RFC 7636) is required on the code grant**, with exactly the one exemption OAuth 2.1
§7.5.1.1 and RFC 9700 §2.1.1 allow. `plain` is rejected; only `S256`.

- A **public** client never goes without it.
- A **confidential** client goes without it only when the host registered it with
  `requirePkce: false` **and** the request carries a `nonce`. The "reasonable assurance, in the
  specific deployment" OAuth 2.1 asks for is a registration decision the host makes; the `nonce`
  is the per-request half. A request without one is refused as if the client had never opted out.
- **Required is the default** on every path that creates a client. A dynamically registered
  client cannot opt itself out (FR-C9) — registering is no assurance of anything — but the host's
  `onRegister` may exempt a confidential one, which is the host vouching for it.
- A `code_challenge`, once sent, is enforced whether or not the client could have omitted it
  (RFC 9700 §2.1.1), and a `code_verifier` for a code issued without a challenge is refused — the
  PKCE downgrade defence (RFC 9700 §4.8.2, OAuth 2.1 §4.1.3).

**FR-C4 — Client authentication.** All of `none`, `client_secret_basic`, `client_secret_post`,
`client_secret_jwt`, `private_key_jwt` (RFC 7523), `tls_client_auth` and
`self_signed_tls_client_auth` (RFC 8705).

The mTLS methods need the host to pass the _verified_ client certificate in — the core never
terminates TLS (FR-R4), so it establishes which client presented a certificate, not whether to trust
it. They are refused at construction, and absent from discovery, where the runtime cannot supply one
(FR-R5, `G-8`).

A JWT assertion is checked for its audience, a `jti` that has not been seen, and a lifetime under
five minutes. The audience is what stops an assertion made out to this provider being replayed at
another one; without it, every provider a client talks to could impersonate it everywhere else.

**FR-C5 — UserInfo endpoint.** Claims resolved per request through `AccountStore.claims`, never
served from a copy cached at authentication time. Signed and/or encrypted responses when the
client asks for them.

**FR-C6 — Discovery.** `/.well-known/openid-configuration` (OIDC Discovery 1.0), advertising only
what the running configuration actually supports, and `/.well-known/oauth-authorization-server`
(RFC 8414). Protected-resource metadata (RFC 9728) is built for each configured resource by
`protectedResourceMetadata`, for the resource server to serve: the URL is the resource server's, not
the provider's.

**FR-C7 — Device authorization grant** (RFC 8628), including the user-code interaction screen.

**FR-C8 — Revocation (RFC 7009) and introspection (RFC 7662).** Introspection requires client or
resource-server authentication and returns `active: false` rather than an error for anything the
caller may not see.

**FR-C9 — Dynamic client registration** (OIDC DCR 1.0) with registration access tokens, gated by
an explicit policy: open, software-statement-gated, or disabled. **Disabled is the default.**
Offering it does not make oidcraft a Dynamic OpenID Provider (OIDC Core §15.2; FR-C1, FR-C12).

**FR-C10 — JWKS endpoint and key rotation.** Multiple active keys; the first signing-capable key
of an algorithm signs, the rest only verify, so a rotation never invalidates live tokens (NFR-S7).

**FR-C11 — Logout.** RP-initiated logout, front-channel logout and back-channel logout. Session
Management 1.0's `check_session_iframe` is **not** implemented — third-party cookie blocking has
made it non-functional in current browsers.

**FR-C12 — Request objects.** JAR (RFC 9101) **by value** (`request`) and PAR (RFC 9126), with
per-client `require_pushed_authorization_requests`.

JAR _by reference_ — a `request_uri` pointing at the client's own server — is not implemented, and
will not be in the core: resolving it means fetching a URL the client chose, which is outbound I/O
the core does not perform (FR-A1, FR-R4). A host that needs it supplies `resolveClientJwks`-style
resolution and pushes the result. A `request_uri` issued by PAR is a different thing: it references
this provider's own storage.

**FR-C13 — Sender-constrained tokens.** DPoP (RFC 9449) with nonce support and `dpop_jkt`, binding
the authorization code to the client's key, from the request or from a proof on its push (§10); and
mTLS certificate-bound tokens (RFC 8705 §3).

**FR-C14 — `iss` in the authorization response** (RFC 9207), always, unconditionally.

**FR-C15 — Rich authorization requests** (RFC 9396), with the host supplying the
`authorization_details` type schemas and their consent rendering.

**FR-C16 — Step-up authentication** (RFC 9470): a resource server can demand a higher `acr` or a
fresher `auth_time`, and the OP must honour the resulting `acr_values`/`max_age`.

**FR-C17 — CIBA** — OpenID Connect Client-Initiated Backchannel Authentication, poll and ping
modes. Push mode is out of scope.

Identifying the user from a hint has no default and never will: the client never touches the user's
browser, so who to reach is entirely the provider's decision, and a library guessing which
`login_hint` means which account would be inventing an authentication decision. `resolveCibaUser`
is required, and CIBA is refused without it.

**FR-C18 — Pairwise subject identifiers** (`sector_identifier_uri`), alongside public ones. A
registered `sector_identifier_uri` is fetched through a host-supplied resolver (FR-A1) and
registration fails unless it lists every `redirect_uri` (OIDC DCR 1.0 §5); a pairwise client whose
redirect URIs span several hosts must register one (OIDC Core §8.1).

**FR-C19 — Resource indicators** (RFC 8707). The host configures the resources tokens may be issued
for — an MCP server, an API — each optionally tied to the resource-server client that introspects for
it. A `resource` on the authorization, token or refresh request must be one of them, or the request
fails with `invalid_target`; the access token's audience is then that resource alone, and only its
resource server may introspect it. A token request may narrow to any configured resource when the
authorization named none, and only to those it named when it did. Without `resource`, nothing changes.
This is what an MCP authorization server owes an MCP server (MCP 2026-07-28): a token issued for one
MCP server is useless at another.

**FR-C20 — Client ID Metadata Documents** (draft-ietf-oauth-client-id-metadata-document), the way
MCP 2026-07-28 prefers a client be known: its `client_id` is an `https` URL serving its own metadata,
with no registration step. The core does not fetch it (FR-A1): the host's `resolveClientMetadata` does,
with its own network policy, size limit, caching and trust policy, and the core checks the result —
a canonical `https` URL with a path and nothing else, refused before any fetch otherwise; a document
whose `client_id` is that URL exactly; no shared secret, so `none` or `private_key_jwt` only; redirect
URIs that are the client's registration, `http://localhost` among them unless it says it is `web`.
PKCE is always required. A stored client with the same id wins. The consent screen shows the
client's host, the host the person returns to, and warns when that is this computer.

**FR-C21 — FAPI 2.0 Security Profile**, opt-in per provider or per client, never a change of the
defaults. Under it the provider refuses what it otherwise only supports: a public client; client
authentication other than `private_key_jwt` or mTLS; an authorization request not pushed (PAR,
`request_uri` under 600 s); a token that is not sender-constrained (DPoP or mTLS); signing
algorithms other than PS256, ES256 and EdDSA; a
client assertion whose `aud` is not exactly the issuer; an assertion outside the 10 s `iat` / 60 s
`nbf` window; an `http` redirect for a client that is not native. `dpop_jkt` (FR-C13) is supported
but not required: the profile asks the server to offer code binding, and its conformance plan's own
happy flow sends none. Refresh tokens follow FR-T3's
exception. It is one switch, never assembled from individual settings: under it the provider refuses
to start on a configuration that cannot meet it (NFR-D2), a client that cannot meet it is refused at
registration and upsert, and discovery advertises only what it allows. Verified by the OpenID Foundation's FAPI 2.0 test plan in CI, as NFR-C1 does for `basic`
and `config`. Message Signing is a separate profile and not part of this.

## 4. Tokens — `FR-T*`

**FR-T1** — ID tokens are always JWS; `none` never. An `RS256` key is mandatory in every key set
and `RS256` is always advertised (OIDC Core §15.1, Discovery 1.0 §3). A client's registered
`id_token_signed_response_alg` is honoured; without one, a configured client gets the provider's
first key (`ES256` by default) and a dynamically registered one `RS256` (OIDC DCR 1.0 §2).

**FR-T2** — Access tokens are opaque by default and JWT (RFC 9068) when a client or resource
server is configured for it. Opaque is the default because a revoked opaque token stops working
immediately and a revoked JWT does not.

**FR-T3** — Refresh tokens rotate on every use. Reuse of a consumed refresh token revokes the
entire grant (RFC 9700 §4.14.2). This is not configurable. The one exception is a client under the
FAPI 2.0 profile (FR-C21): confidential, authenticating with a key, and holding sender-constrained
tokens, so its refresh token is useless without that key and rotation would only lose grants to a
dropped response (FAPI 2.0 Security Profile §5.3.2.1). Its refresh token does not rotate; it still
expires, and is still revoked with its grant.

**FR-T4** — Authorization codes are single-use with the same consequence on replay: consuming a
code twice revokes the grant it belongs to.

**FR-T5** — Every artifact carries an absolute expiry that storage enforces, so a store that
misses a prune cycle still cannot serve an expired token.

**FR-T6** — A refresh token without `offline_access` is bound to the session it was issued in: it
expires no later than that session and dies when the session ends, logout included. Only the
authorization code grant issues one, to a client registered for `refresh_token`; a device or CIBA
approval's session is the approver's browser, not the client's, so those still need `offline_access`. It rotates as
FR-T3 says. One with `offline_access` outlives the session (OIDC Core §11), within `refreshToken`
idle and `refreshTokenFamily` absolute lifetimes. A browser client renews without a third-party
cookie, and a stolen session-bound token is good only while the session lasts.

## 5. Storage — `FR-A*`

**FR-A1** — Storage is reached only through the `Adapter` capability interfaces
(`ARCHITECTURE.md` §4). The core performs no I/O of its own and holds no in-process state that
survives a request, so two processes behind a load balancer behave identically to one.

**FR-A2** — An adapter is a set of narrow, typed stores (`ClientStore`, `ArtifactStore`,
`SessionStore`, `GrantStore`, `AccountStore`, `KeyStore`, `ReplayGuard`, and optionally
`LinkedIdentityStore`) — not one stringly-typed blob table keyed by model name.

**FR-A3** — A `KvStore` implementation (`find`/`upsert`/`destroy`/`insert`/`scan`) is sufficient to
derive a complete `Adapter`, so a new backend is a day's work rather than a week's. `insert` must
write only if the key is absent, atomically: single use (FR-T3, FR-T4, NFR-S4) cannot be built from
a read followed by a write, so an eventually consistent store cannot back a provider.

**FR-A4** — First-party adapters ship for **Drizzle** (Postgres and SQLite), **Kysely**
(Postgres, SQLite) and **TypeORM** (FR-A6), plus an in-memory one for tests. Each ships its schema as migrations
the host runs, never as something the library applies at boot.

**FR-A5** — Adapters that own their schema must expose real columns and indexes for every value
the core queries by (`grant_id`, `user_code`, `expires_at`, `account_id`, upstream session id). A
JSON blob with no index is a correctness problem at revocation time, not just a slow one.

**FR-A6** — The TypeORM adapter is first-party: its own `oidcraft/adapters/typeorm` entry with
`typeorm` as an optional peer, passing the same conformance suite as the others (FR-A3). A
third-party adapter is an ordinary package depending on `oidcraft` and implementing `Adapter`;
nothing about the contract is internal.

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

**FR-I3** — The library ships the rules the screens enforce (`oidcraft/interaction`) and no
markup. Reference screens for login, consent, account selection, upstream selection, device-code
entry and logout confirmation live in the reference deployment, which a host replaces wholesale.

**FR-I4** — Consent is remembered as a durable `Grant`, so a returning user is not asked again for
scopes already granted, and revoking the grant re-asks.

**FR-I5** — `prompt=none`, `prompt=login`, `prompt=consent`, `prompt=select_account` are all
honoured, including the error responses when `none` cannot be satisfied.

**FR-I6** — `ui_locales` selects the screen language; the reference screens ship English and are
structured for translation.

**FR-I7** — An optional `oidcraft/accounts` entry implements `AccountStore` over the `Adapter`'s
`credentials` store. It is a subpath entry like any other, so a host that brings its own
`AccountStore` pulls none of it, and nothing in the core assumes it. It covers:

- **Passwords**, hashed with argon2id by a `PasswordHasher` the host passes in. The library ships
  one per runtime that has a native argon2 (`./runtimes/bun`, `./runtimes/node`) and none of its own,
  so no runtime's global leaks into the entry. An unknown username costs the same hash as a known one.
- **TOTP** (RFC 6238) as a second factor: begin, confirm with a first code, verify, remove. A code is
  accepted once (NFR-S5). The secret is stored encrypted with AES-GCM under a key the host
  configures, bound to its account, so a database dump alone yields no second factor.
- **Recovery codes**, issued when TOTP is confirmed, stored hashed and each usable once.
- **Throttling**: failed passwords and codes lock the account for a while (NFR-S3).
- **Password reset**: single-use tokens with a short lifetime, stored hashed. Delivering one is I/O,
  so the host sends it (FR-A1). Completing a reset ends the account's sessions.
- **Self-service sign-up**, which the host may leave unmounted.

## 8. Administration — `FR-M*`

**FR-M1** — A management API over clients, grants, sessions, keys and upstream providers, exposed
as fetch handlers the host mounts behind its own authentication. **The library never decides who
is an administrator.**

**FR-M2** — A reference admin UI covering client CRUD, key rotation, upstream configuration,
session inspection and grant revocation.

**FR-M3** — Every write through the management API emits an audit event. The host decides where
audit events go; the library does not persist them.

**FR-M4** — Several issuers in one process are possible and never imposed. `createRealms` builds an
ordinary provider per realm on first use, from a realm record and a host-supplied `configure`; a
single-issuer deployment uses `createProvider` alone and meets no realm, default realm or URL
convention. The library owns the records (an optional `RealmStore`) and their lifecycle — create,
update, enable, disable, remove, each audited — and calls the host's `provision` and `retire`, since
creating and dropping a realm's storage is the host's. A request only selects a realm: an id is a
DNS label, and an unknown or disabled one resolves to nothing. Each realm has its own storage and
keys, and two realms sharing a signing key are refused.

## 9. Runtime — `FR-R*`

**FR-R1** — The core's only inputs are a WHATWG `Request` and configuration; its only output is a
`Response`. No `node:*` import anywhere in its graph.

**FR-R2** — All cryptography goes through WebCrypto (`crypto.subtle`, `crypto.getRandomValues`)
via `jose`. No `node:crypto`, no native addon, no dependency on a C++ build.

**FR-R3** — Supported hosts: Bun ≥ 1.4, Node ≥ 22, Deno, and workerd-shaped runtimes.

Only **Node** needs an HTTP bridge, because `node:http` speaks `IncomingMessage`/`ServerResponse`
rather than `Request`/`Response`. Bun, Deno and workerd hand the core a `Request` and take a
`Response`, so it mounts into their servers directly.

Every runtime nonetheless needs a small **context provider**, because what FR-R4 requires is not
carried by `Request` on any of them, and each exposes it differently: `server.requestIP(request)`
on Bun, the `info.remoteAddr` second argument on Deno, `req.socket` on Node, `request.cf` and
`CF-Connecting-IP` on workerd. One entry per runtime under `oidcraft/runtimes/*`, each touching only
its own globals and containing no protocol logic.

**FR-R4** — Everything the core cannot learn from the `Request` — the verified client TLS
certificate, the real client IP, the deployment's public origin — arrives as an explicit
`RequestContext`. The core never reads `X-Forwarded-*` on its own authority (NFR-S6).

**FR-R5** — A capability the running runtime cannot supply disables the features that need it,
loudly, at construction rather than at the first request (NFR-D2). The mTLS client-authentication
methods (FR-C4) and certificate-bound tokens (FR-C13) require `RequestContext.clientCertificate`;
where no provider can supply one, advertising them in discovery would be a lie (`G-8`).

## 10. Non-functional

### Security — `NFR-S*`

**NFR-S1** — RFC 9700 (BCP 240) is the baseline, not a later hardening pass. Where it and OIDC
Core disagree, RFC 9700 wins and the deviation is documented here. OAuth 2.1
(`draft-ietf-oauth-v2-1`, read at -16) binds the server too, although still a draft, and wins over
OIDC Core the same way. The one deviation that costs anything: a confidential client sending neither
PKCE nor a `nonce` is refused (FR-C3, OAuth 2.1 §7.5.1.1), which OIDC Core would allow.

**NFR-S2** — Redirect URIs match by exact string comparison. No wildcards, no prefix matching. The
one exception is the port of an `http` loopback IP literal (`127.0.0.1`, `[::1]`), which a native app
chooses per request (RFC 8252 §7.3, RFC 9700 §2.1). The hostname `localhost` gets no port exception;
a client registered as `application_type: native` may use `http://localhost` redirect URIs, matched
exactly, because MCP clients do (MCP 2026-07-28). A `web` client, the default, may not.

**NFR-S3** — Every token, code and identifier is generated with `crypto.getRandomValues` at ≥ 256
bits of entropy and compared in constant time where compared at all — except a code a person types
(the device `user_code`, FR-C7), which follows RFC 8628 §6.1 and is protected by rate limiting and a
short lifetime instead (RFC 8628 §5.1).

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
for the `basic` and `config` OP profiles. A red suite is a failed build, except for the modules
`conformance/README.md` lists as refused on purpose, each with the clause that requires the refusal.
`dynamic` is not a target: it tests a Dynamic OpenID Provider, which FR-C1 rules out.

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

**NFR-D4** — Zero runtime dependencies beyond `jose`. `drizzle-orm`, `kysely` and `typeorm` are optional peers
confined to their own subpath entries, so importing the core pulls neither. The relying-party code
`oidcraft/broker` needs is this workspace's own and is bundled into that entry rather than
depended on, so brokering adds no third-party package either.

## 11. Open questions — `G-*`

**G-1 — OpenID Federation 1.0 (trust chains, not brokering).** Not "sign in with Google": that is
identity brokering (FR-F*), and it is built. OpenID Federation lets parties that never registered
with each other trust one another through signed entity statements and a trust anchor — Italy's
SPID/CIE, EU identity wallets, research federations. Decided: not planned unless a deployment in one
of those ecosystems needs it. Resolving a trust chain is outbound fetching the core does not do
(FR-A1), so it would arrive as its own entry with a host-supplied fetcher, and nothing in the core
assumes it away.

**G-3 — FAPI 2.0.** Decided: the Security Profile as FR-C21. Its conflict with FR-T3 — §5.3.2.1
says the server "shall not use refresh token rotation except in extraordinary circumstances" — is
resolved by FR-T3's exception for exactly the clients the profile allows, which RFC 9700 §4.14.2
permits (rotation or sender-constraining, and only of public clients), rather than by FAPI's
alternative of rotation with a retry window, which would weaken reuse detection for everyone in the
profile.

**G-4 — Upstream SAML.** Decided against, in-tree. Validating XML signatures is a history of
signature-wrapping and canonicalisation vulnerabilities, it would bring a large XML-crypto
dependency, and the enterprise IdPs that once needed it (ADFS, Entra ID, Okta, Ping) speak OIDC. A
host that must accept SAML puts a SAML-to-OIDC bridge upstream and brokers to it as an OIDC
provider, or implements `UpstreamProvider` itself.

**G-6 — Multi-tenancy.** Answered by FR-M4, with storage per realm. Shared tables — a realm column
in every table and query — are decided against: isolation would then rest on every query of five
adapters remembering a filter, and one that forgets serves another realm's clients, grants or
identities. Per-realm storage makes that structural. A deployment with more realms than it wants
databases scopes one backend instead: a Redis `prefix`, a Postgres schema, a SQLite file each.

**G-8 — mTLS on Bun.** `Bun.serve` accepts `tls.requestCert`, so the handshake can ask for a client
certificate, but its `Server` interface exposes only `requestIP`, `timeout`, `upgrade`, `publish`
and `ref`/`unref` — no peer-certificate accessor. So `tls_client_auth`,
`self_signed_tls_client_auth` (FR-C4) and certificate-bound tokens (FR-C13) are not implementable
on Bun today without dropping to `node:tls`. Re-verified on Bun 1.4.4 on 2026-10-28: a handshake
with `requestCert` succeeds and is verified, but `Bun.serve` hands the handler nothing, and
`node:https` (oven-sh/bun#16834) now reports `authorized: true` with an empty certificate — no
subject, no DER, no fingerprint. Only `node:tls` and `Bun.listen` sockets expose it.
Decided: they stay unavailable on Bun (FR-R5) until Bun exposes the certificate. DPoP (FR-C13's
alternative) and `private_key_jwt` cover sender-constraining and client authentication there, as
FAPI 2.0 itself accepts. A header from a trusted mTLS-terminating proxy was designed and not built:
every host enabling it must make the proxy overwrite that header, and a misconfiguration is client
impersonation the library cannot detect. Build it if an mTLS-only deployment on Bun appears. Node
and workerd are unaffected.
