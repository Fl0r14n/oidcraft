---
title: Security posture
description: The rules oidcraft will not bend, why, and what it has not proved.
---

# Security posture

This page lists the rules oidcraft enforces whatever the configuration says, the reason for each, and
the requirement that states it. It then lists what is missing, undecided or unproven. Read the second
half as carefully as the first.

## Where the project stands

Read this before anything else on the page.

- **Conformance runs in CI. That is not certification.** The OpenID Foundation conformance suite's
  `basic` and `config` plans gate the build (NFR-C1), and so does the FAPI 2.0 Security Profile plan
  against the demo server with the profile switched on (FR-C21). Some modules fail or are skipped on
  purpose. `conformance/README.md` lists each one with the clause behind the refusal. Others end in
  REVIEW, the suite's state for "a person must look at the screenshot". Certification means someone
  reviews those modules and signs them off. Nobody has.
- **No production deployment.** No deployment has run oidcraft in production, against a relying
  party not written in this repository, or under any load. Nobody has load-tested it.
- **No independent review.** No security firm or third party has reviewed the code. The one review
  so far was by agents reading the code against `REQUIREMENTS.md`, which narrowed the search rather
  than ending it. In the plan's words, no `FR-*` "has been checked by anything but its author and its
  tests".
- **Version `0.x`, tracking `main`.** The API will change, and these pages describe `main`, not a
  release.

[The plan](/reference/plan) is the authority on this section. If the two disagree, trust the plan.

## The baseline

RFC 9700 (BCP 240) is the baseline from the start, not a hardening pass added later. OAuth 2.1 binds
the server too, although it is still a draft. Where either disagrees with OpenID Connect Core, the
OAuth document wins (NFR-S1). Only one deviation costs anything in practice: a confidential client
that sends neither PKCE nor a `nonce` is refused, where OIDC Core would let it through. The basic
conformance plan has one module that expects otherwise, and it fails on purpose.

Everything below follows from that baseline. Each rule says whether you can configure it. Most you
cannot, and that is deliberate. A flag that turns off a defence will eventually be turned off, and
the provider would go on advertising itself as compliant.

## The non-negotiables

### PKCE on every authorization code

FR-C3 requires PKCE (RFC 7636) on the code grant, with exactly the one exemption that OAuth 2.1
§7.5.1.1 and RFC 9700 §2.1.1 allow. Only `S256` is accepted. `plain` is refused from every client.

- **A public client never goes without PKCE.** No setting changes this.
- **A confidential client goes without PKCE only when two things hold.** The host registered it with
  `requirePkce: false`, and the request carries a `nonce`. OAuth 2.1 asks for "reasonable assurance,
  in the specific deployment". The registration is the host deciding that assurance exists; the
  `nonce` is the half that comes with each request. A request without a `nonce` is refused as if the
  client had never opted out.
- **Required is the default on every path that creates a client.** A dynamically registered client
  cannot opt itself out, because registering proves nothing about it. The host's `onRegister` may
  exempt a confidential client, which is the host vouching for it. A public client cannot be exempted
  even then.
- **PKCE is required for every Client ID Metadata Document client** (FR-C20).
- **The downgrade defence.** Once a client sends a `code_challenge`, it is enforced, even if the
  client could have omitted it. A `code_verifier` sent for a code issued without a challenge is
  refused, which closes the PKCE downgrade attack (RFC 9700 §4.8.2).

**Configurable?** Only per client, through `requirePkce: false`, and only for a confidential client.
Even then a request without a `nonce` is refused. No provider-wide switch exists.

### Refresh tokens rotate, and reuse revokes the family

FR-T3: a refresh token rotates on every use. Each authorization — a code redeemed, a device or CIBA
request approved — starts a family, and every token issued from it belongs to it. Presenting a
consumed refresh token revokes that family (RFC 9700 §4.14.2). A stolen token is then a race between
the thief and the legitimate client, and whichever one loses reveals the theft and ends the family
for both. The grant is one per account and client, so the same app signed in on another device is a
different family and keeps working: what leaked was one device's token, not the consent.

There is one exception. Under the FAPI 2.0 profile (FR-C21), a client is confidential, authenticates
with a key, and holds sender-constrained tokens. Its refresh token is useless without that key, and
rotating it would only lose grants when a response gets dropped (FAPI 2.0 Security Profile
§5.3.2.1). Its refresh token does not rotate. It still expires, and it is still revoked with its
grant. G-3 records why this exception was chosen over FAPI's alternative, rotation with a retry
window: that alternative would weaken reuse detection for every client under the profile.

A refresh token issued without `offline_access` is also bound to its session: it expires no later
than the session and dies when the session ends, logout included, at the token, introspection and
token exchange endpoints alike (FR-T6).

**Configurable?** No. FR-T3 says so in as many words. You get the exception only by putting the
client under the FAPI 2.0 profile, which is a single switch that brings all of that profile's other
refusals with it. Nothing turns off rotation on its own.

### Replaying a single-use artifact revokes what it produced

FR-T4: an authorization code is single-use, and redeeming it a second time revokes the family it
started. NFR-S4 states the general rule. A replay means the artifact leaked, so everything derived
from it has to stop working too. The replay reaches `onAudit` as `token.replay` (FR-M3).

This is only as strong as the storage underneath it. Single use cannot be built from a read followed
by a write. FR-A3 therefore requires an adapter's `insert` to be atomic, so a store that is only
eventually consistent cannot back a provider. Redis `SET NX`, a Durable Object or a single-process
`Map` qualify. Workers KV does not. The shared adapter conformance suite races eight concurrent
callers against each atomic operation ([ARCHITECTURE.md §4.1](/reference/architecture#_4-1-why-not-oidc-provider-s-shape)).
If you write your own adapter, run that suite against it.

**Configurable?** No.

### Redirect URIs match exactly

NFR-S2: redirect URIs are compared by exact string match. No wildcards, no prefix matching. The one
exception is the port of an `http` loopback IP literal (`127.0.0.1`, `[::1]`), which a native app
picks per request (RFC 8252 §7.3). The hostname `localhost` gets no port exception. A client
registered as `application_type: native` may use `http://localhost` redirect URIs, matched exactly,
because MCP clients do. A `web` client, the default, may not.

An unknown `client_id` or an unregistered `redirect_uri` produces an error page, never a redirect.
Redirecting there would turn the provider into an open redirector.

**Configurable?** No.

### `iss` in every authorization response

FR-C14: the `iss` parameter (RFC 9207) is in the authorization response always, unconditionally. A
client that talks to several providers can then tell which one answered, which is the defence
against mix-up attacks.

**Configurable?** No.

### No token in the front channel

FR-C1: the only response type is `code`. Implicit and hybrid flows are not implemented and are not
advertised. OAuth 2.1 removes them, and anything that returns a token through the front channel
hands it to the browser's history and `Referer`. FR-C2 likewise leaves out the `password` grant.
The cost is real: oidcraft is not a Dynamic OpenID Provider in the sense of OIDC Core §15.2.

FR-T1: ID tokens are always signed, and the `none` algorithm is never used. Access tokens are opaque
unless a client or resource server is configured for JWT (FR-T2), because a revoked opaque token
stops working immediately and a revoked JWT does not.

**Configurable?** You can choose JWT access tokens. You cannot enable implicit, hybrid, `password`
or unsigned ID tokens.

### Account linking by `(provider, subject)`, never by email

FR-F5 and NFR-S8: when the provider brokers to an upstream, a returning identity is linked to a local
account by the upstream's issuer and `sub`, and nothing else. Matching by email address hands over
the account the moment an upstream does not verify addresses, or lets a user change theirs.

Two other policies exist. `verified-email` requires `email_verified` from the upstream.
`interactive` makes the person prove control of the existing account before linking. Either must be
chosen deliberately, and neither is the default
([ARCHITECTURE.md §5.5](/reference/architecture#_5-5-the-linking-hazard)). FR-F7 adds that `sub` is
never taken from anywhere but the upstream `sub`, and that no upstream claim becomes a local one
unless a mapper says so.

**Configurable?** Yes, per broker. The default is the safe one, and it will stay the default.

### The issuer is configuration, never a header

NFR-S6: the issuer identifier is configuration. It is never derived from the `Host` or
`X-Forwarded-Host` header, which would let a request rewrite the issuer of the tokens it receives.
FR-R4 extends the rule. Whatever the core cannot learn from the `Request` (the verified client
certificate, the real client IP, the public origin) arrives as an explicit `RequestContext` from the
runtime's context provider. The core never reads `X-Forwarded-*` on its own authority.

The Node context provider can read the client IP from `X-Forwarded-For`, but only if you pass
`trustProxy`, and only the right-most address, the one your own proxy appended. It never derives the
issuer from a header. Turn `trustProxy` on only when a proxy you control is the only thing that can
reach the process. See [the runtimes page](/guide/runtimes) for what each runtime's context provider
reads.

**Configurable?** The issuer is something you set; nothing can override it from a request.

### The library never decides who is an administrator

FR-M1: the management API over clients, grants, sessions, keys and upstreams is a set of functions
the host mounts behind its own authentication. oidcraft has no notion of an admin user, an admin
role or an admin scope. Every write through it emits an audit event, as do a replayed token and a
failed client authentication, and the host decides where audit events go (FR-M3).

**Configurable?** Not applicable. Deciding who is an administrator is your job, and there is no
default to fall back on.

### Some decisions have no default

A library that guessed these would be inventing a security decision on the host's behalf, so it does
not:

- **CIBA:** which account a `login_hint` means. CIBA is refused without `resolveCibaUser` (FR-C17).
- **Token exchange:** who may act as whom. `exchangePolicy` has no default (FR-C2).
- **Dynamic client registration:** disabled unless turned on (FR-C9).
- **Upstream access and refresh tokens:** not stored unless a provider opts in. When stored, they are
  encrypted at rest by the adapter and never returned to a downstream client by default (FR-F10,
  NFR-S9).

### The rest of `NFR-S*`

- **Randomness and comparison (NFR-S3).** Every token, code and identifier comes from
  `crypto.getRandomValues` with at least 256 bits of entropy, and is compared in constant time where
  it is compared at all. The exception is the device `user_code`, which a person types. It follows
  RFC 8628 §6.1 and is protected instead by a short lifetime and a limit on wrong guesses per client
  IP.
- **One-time values (NFR-S5).** `jti`, DPoP proofs and upstream nonces are checked against
  `ReplayGuard` within their validity window. A JWT client assertion is also checked for its audience
  and for a lifetime under five minutes. Without the audience check, any provider a client talks to
  could replay that client's assertions at the others (FR-C4).
- **Key rotation (NFR-S7).** Verification keys outlive the signing key by at least the longest token
  lifetime, so a rotation never invalidates a live token (FR-C10).
- **Nothing bearer at rest (NFR-S11).** Codes, access and refresh tokens, device codes, pushed
  request references, registration access tokens and reset tokens are stored under a SHA-256 of
  their value, so a copy of the database redeems nothing. So is a client secret used with
  `client_secret_basic` or `client_secret_post`: registration and `management.clients.create` return
  a generated one once, and a lost one is replaced with `management.clients.rotateSecret`. A client
  you seed through the adapter yourself stores `clientSecretHash: await hashClientSecret(secret)`.
  The hash is unsalted, which protects a generated secret and not a short chosen one, so the
  management API refuses a supplied secret under 32 characters; seed generated ones too. Management
  never hands a hash out.
  `client_secret_jwt` keeps its secret readable, as the HMAC key it is, which is a reason to prefer
  `private_key_jwt`. The session cookie carries a secret too: the session is stored under its
  SHA-256, which is also the ID token's `sid`.
- **Logs (NFR-S10).** No secret is ever logged. A token appears in a log, if at all, as a prefix and
  a hash.

## What stays your job

The core performs no I/O and holds no state (FR-A1), and that boundary puts some security work on
the host:

- **TLS.** The core never terminates TLS. For mTLS your context says whether your listener verified
  the certificate's chain; `tls_client_auth` accepts only a verified one, while the self-signed
  method and certificate-bound tokens rest on the key the handshake proved (FR-C4, RFC 8705 §2).
- **Outbound fetches.** `resolveClientJwks`, `resolveSectorIdentifier` and `resolveClientMetadata`
  are yours because each one fetches a URL that someone else chose. Your network policy, size limit
  and caching are what stand between those URLs and your internal network. FR-C20 spells this out
  for metadata documents: block private addresses, cap the body, apply your trust policy.
- **Request size.** The core reads whatever body arrives. Cap it in front of the provider, beside
  your rate limits (NFR-S12).
- **Delivering logout.** The core mints back-channel logout tokens and hands them to `onLogout`. It
  never POSTs them itself (FR-C11).
- **Keys, https and admin authentication.** See
  [Before production](/guide/provider#before-production) in the provider guide.
- **The context provider.** Without a client IP, every caller's wrong device-code guesses count
  against one shared anonymous bucket, so a stranger can lock out device-code entry for everyone.
  Mount the context provider for your runtime ([runtimes](/guide/runtimes)).

## Known gaps and open questions

### mTLS is unavailable on Bun (G-8)

`Bun.serve` can ask for a client certificate during the TLS handshake, but it gives the request
handler no way to read the certificate. As of Bun 1.4.4 (re-checked 2026-10-28), `node:https` under
Bun reports a verified handshake with an empty certificate. Only `node:tls` and `Bun.listen` sockets
expose it. On Bun, therefore, `tls_client_auth`, `self_signed_tls_client_auth` (FR-C4) and
certificate-bound tokens (FR-C13) are refused at construction and are absent from discovery (FR-R5).
Advertising them would be a lie.

On Bun, DPoP and `private_key_jwt` cover sender-constraining and client authentication, which FAPI
2.0 itself accepts. Another design was considered and not built: trusting a header set by an
mTLS-terminating proxy. Every host enabling it would have to make the proxy overwrite that header,
and getting that wrong means client impersonation the library cannot detect. It gets built only if
an mTLS-only deployment on Bun turns up. Node and workerd are unaffected.

### The other open questions

- **G-1: OpenID Federation 1.0** (trust chains, not brokering). Not planned unless a deployment in
  one of those ecosystems needs it.
- **G-3: FAPI 2.0.** Decided: the Security Profile ships as an opt-in (FR-C21). The FAPI 2.0
  Message Signing profile is a separate profile and is not part of it. NFR-C2 still describes FAPI
  2.0 as a target for a later milestone, but the profile is implemented and its plan runs in CI.
- **G-4: upstream SAML.** Decided against, in-tree. XML signature validation has a long history of
  signature-wrapping and canonicalisation vulnerabilities. A host that must accept SAML puts a
  SAML-to-OIDC bridge upstream and brokers to it.
- **G-6: multi-tenancy.** Each realm gets its own storage, never shared tables. With shared tables,
  isolation would depend on every query in five adapters remembering a filter. Two realms sharing a
  signing key are refused (FR-M4).

### Not supported, on purpose

Some conformance modules fail or are skipped on purpose. `conformance/README.md` lists each one with
the clause behind the refusal.

- **No `nonce` and no PKCE from a confidential client:** refused (FR-C3, NFR-S1).
- **Unsigned (`alg: none`) request objects:** refused (FR-C12).
- **The `claims` request parameter:** not supported. OIDC Core leaves it optional.
- **JAR by reference** (a `request_uri` pointing at the client's own server): not implemented and
  never will be in the core. Resolving it means fetching a URL the client chose (FR-C12).
- **Implicit and hybrid flows:** not implemented, so oidcraft is not a Dynamic OpenID Provider
  (FR-C1).
- **Session Management's `check_session_iframe`:** not implemented. Third-party cookie blocking has
  made it non-functional in current browsers (FR-C11).
- **CIBA push mode:** out of scope (FR-C17).

### Known weaknesses in what is built

- **The device-code guess counter can be raced.** The wrong-`user_code` counter is a plain
  read-modify-write, so a burst can get a few guesses past the limit. The local-accounts counters do
  not have this property: each attempt claims its slot atomically before the hash is checked
  ([ARCHITECTURE.md §6.1](/reference/architecture#_6-1-local-accounts)).
- **A missing FAPI key fails late.** Signing keys are only readable asynchronously. A provider under
  the FAPI 2.0 profile with no PS256, ES256 or EdDSA key is therefore refused at its first signature,
  not at construction (ARCHITECTURE.md §3.3).
- **Third-party adapters need their own proof.** Atomic single use is a property of the adapter, not
  the core. An adapter that has not passed the shared conformance suite has not shown it.
