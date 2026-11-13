---
title: Coming from oidc-provider
description: How oidc-provider's concepts map onto oidcraft, what differs and why, and when oidc-provider is the better choice.
---

# Coming from `oidc-provider`

[`oidc-provider`](https://github.com/panva/node-oidc-provider), by Filip Skokan (panva), is the
reference OpenID Provider implementation for Node.js, and oidcraft owes a lot to it. This page is for
someone who knows it: how its concepts map onto oidcraft's, where oidcraft deliberately does
something else, and when you should stay with `oidc-provider`.

Statements about `oidc-provider` here come from its README and its
[configuration documentation](https://github.com/panva/node-oidc-provider/blob/main/docs/README.md)
as they read in November 2026. Those documents are the authority. If one of them disagrees with this
page, trust the document.

## When `oidc-provider` is the better choice

The honest answer comes first.

- **You need certification.** `oidc-provider`'s README lists OpenID Certification for a long list of
  profiles: Basic, Implicit, Hybrid, Config, Form Post and 3rd Party-Init OP, Back-Channel and
  RP-Initiated Logout, FAPI 1.0, FAPI CIBA and FAPI 2.0. oidcraft passes the `basic`, `config` and
  FAPI 2.0 conformance plans in CI and is not certified ([security posture](/guide/security)).
- **You need something proven in production.** `oidc-provider` is on its ninth major version.
  oidcraft has never run in production, has not been load-tested, and has had no third-party review.
  Its API will change before 1.0.
- **You need implicit or hybrid flows.** `oidc-provider` supports them, with `code id_token` and
  `id_token` among its default `responseTypes`. oidcraft implements only `code`, so it is not a
  Dynamic OpenID Provider (FR-C1).
- **You need FAPI 1.0 Advanced, JARM, FAPI 2.0 Message Signing or FAPI-CIBA.** `oidc-provider` lists
  all four as implemented, with FAPI-CIBA marked experimental. oidcraft implements the FAPI 2.0
  Security Profile only (FR-C21), with no JARM and no Message Signing.
- **You want OpenID for Verifiable Credential Issuance or Attestation-Based Client Authentication.**
  `oidc-provider` lists both as experimental. Verifiable credentials are a non-goal for oidcraft
  (REQUIREMENTS.md §1.1).
- **You want a framework integration on Node.** `oidc-provider`'s documentation covers mounting it
  in connect, express, fastify, hapi, koa and nest applications. oidcraft documents mounting into a
  runtime's own server, so on Node you write the glue to your framework yourself.

oidcraft runs on Bun as well as Node, but mTLS is not available there (G-8). If you need mTLS
and chose oidcraft to run on Bun, you will not get it.

If none of these apply, the rest of this page is about what changes when you switch.

## What oidcraft does differently

`REQUIREMENTS.md` gives three reasons oidcraft exists. Everything else on this page follows from
them.

1. **It is runtime-portable.** `oidc-provider` describes itself as an implementation "for Node.js"
   and is built on Koa. oidcraft's core takes a WHATWG `Request` and returns a `Response`, imports
   nothing from `node:*`, and does its cryptography through WebCrypto. One build runs on Bun, Node,
   Deno and workerd-shaped hosts (FR-R1, FR-R2, FR-R3).
2. **The interaction half comes with it.** `oidc-provider` ships development-only login and consent
   screens, and its documentation says production deployments must disable them and write their
   own. oidcraft ships the rules those screens enforce, a local-accounts implementation with TOTP,
   reference screens, and a management API, so a team does not start from an empty login page
   (FR-I3, FR-I7, FR-M1).
3. **Brokering is a first-class mode.** An oidcraft deployment can be a pure broker in front of
   Entra, Google or another OP, an OP with local accounts, or both. Session provenance,
   re-authentication passthrough and logout propagation are in the core, because none of them can
   be bolted on from outside ([ARCHITECTURE.md §5.3](/reference/architecture#_5-3-why-brokering-lives-in-the-core-not-in-the-app)).

## How the concepts map

### Mounting: Koa versus fetch-in, fetch-out

`oidc-provider` is a Koa application. You construct it as `new Provider(issuer, configuration)`, then
mount it or its `callback()` inside your own framework. `oidcraft` is one function from `Request` to
`Response`: `provider.handle(request)`. It answers the protocol endpoints and returns a 404 for
anything else, so you route your own pages beside it.

Only Node needs an HTTP bridge, because `node:http` does not speak `Request` and `Response`. Every
runtime still needs a small **context provider**, because the client IP and the TLS client
certificate are not carried on `Request` anywhere (FR-R4). This is the biggest operational
difference. See [runtimes](/guide/runtimes) and
[ARCHITECTURE.md §3.1](/reference/architecture#_3-1-request-pipeline).

### Configuration: `new Provider(issuer, configuration)` versus `ProviderConfig`

In both libraries the issuer is passed in explicitly. The difference is what surrounds it.

- **Behind a proxy.** `oidc-provider`'s documentation tells you to set Koa's `proxy = true` so that it
  trusts `X-Forwarded-Proto` and `X-Forwarded-For`. oidcraft's core never reads `X-Forwarded-*`
  (NFR-S6). The only place a forwarded header is read is the Node context provider's opt-in
  `trustProxy`, and it reads only the client IP.
- **Feature flags versus profiles.** In `oidc-provider`, many features are flags under `features.*`,
  several of them off by default, and security behaviour such as PKCE enforcement and refresh-token
  rotation is a function you may override. oidcraft's `ProviderConfig` is typed, and an unsupported
  combination fails at construction, not at the first request (NFR-D2). Its security rules are not
  overridable functions (see the next section). FAPI 2.0 is one switch, `profile: 'fapi2'`, rather
  than a set of settings to assemble (FR-C21).
- **Outbound requests.** oidcraft makes none. Anything that would fetch a URL is a host-supplied
  function, for example `resolveClientJwks` or `resolveClientMetadata`, and anything that would POST
  is a callback, for example `onLogout` for back-channel logout tokens (FR-A1).

For the options themselves, start from the
[provider guide](/guide/provider) and the `ProviderConfig` type's own comments.

### Interactions: `interactionDetails` / `interactionFinished` versus `interactions`

The model is the same, and deliberately so. In both libraries the authorization endpoint redirects
to your interaction app when it cannot decide alone. Your app answers, and the provider re-evaluates
the original request and may ask again (FR-I1, FR-I2; ARCHITECTURE.md §6 calls this
"`oidc-provider`'s model, and it is the right one").

- **Where the browser goes.** `oidc-provider`'s `interactions.url` becomes `interactionUrl` in
  oidcraft.
- **Reading what is asked.** `provider.interactionDetails(req, res)` becomes
  `provider.interactions.find(id)`. It returns a view whose `kind` is `login`, `consent` or `logout`.
- **Answering.** `provider.interactionFinished(req, res, result)` and `interactionResult` become
  `provider.interactions.complete(id, result, cookie)`, with the request's `cookie` header. It returns
  the redirect and any session cookie for you to send, instead of writing to a Node response. Like
  `oidc-provider`'s interaction cookie, the cookie binds the interaction to the browser that started
  it, so the interaction routes are served on the issuer's host.
- **Consent.** In `oidc-provider`, your interaction code builds a `Grant` and saves it. In oidcraft,
  consent is a list of scopes in the result, remembered as a durable grant, so a returning user is
  not asked again and revoking the grant asks again (FR-I4).

[The interaction guide](/guide/interaction) has the tested sample.

### Storage: the adapter class versus `Adapter` and `KvStore`

`oidc-provider`'s adapter is one class, instantiated once per model name (`Session`, `AccessToken`,
`Grant` and so on). Every model shares the same methods: `upsert`, `find`, `findByUid`,
`findByUserCode`, `consume`, `destroy` and `revokeByGrantId`. Its documentation describes the
built-in in-memory adapter as fit for development and testing only.

oidcraft splits storage by capability instead (FR-A2). `ClientStore`, `ArtifactStore`,
`SessionStore`, `GrantStore`, `AccountStore`, `KeyStore` and `ReplayGuard` are required, plus
optional stores for brokering, local accounts and realms. Each method's payload is a real type, and
a relational adapter gets real columns and indexes for the queries the protocol makes: revoke by
grant, find by user code, expire a range (FR-A5).
[ARCHITECTURE.md §4.1](/reference/architecture#_4-1-why-not-oidc-provider-s-shape) explains why:
implementations of the single-class shape tend to end up as one `(kind, id, payload)` table, where
those queries run against JSON extraction instead of an index.

If you want the simple case back, implement a `KvStore`. It has five methods, one of them an atomic
`insert`, and `fromKv` derives a complete adapter from it (FR-A3). First-party adapters ship for
memory, Drizzle, Kysely, TypeORM and Redis, each passing one shared conformance suite. A Drizzle,
Kysely or TypeORM adapter ships migrations for you to run; the library never alters a schema at boot.
[The adapters guide](/guide/adapters) covers writing your own.

### Accounts: `findAccount` versus `AccountStore`

`oidc-provider`'s `findAccount(ctx, id)` returns an object with an `accountId` and a `claims()`
function. oidcraft's `AccountStore` has the same two jobs, as `find(accountId)` and
`claims(accountId, scopes, claims)`. Claims are resolved on every request and never cached at sign-in
(FR-C5).

The difference is that oidcraft can be the account system as well. `@oidcraft/provider/accounts`
implements `AccountStore` with argon2id passwords, TOTP, recovery codes, throttling, password reset
and sign-up (FR-I7). It is optional: bring your own `AccountStore` and none of it is loaded.

### Administration

oidcraft has a management API over clients, grants,
sessions, keys and upstreams, as functions you mount behind your own authentication. Every write
emits an audit event (FR-M1, FR-M3). Several issuers in one process are available through
`createRealms` and never forced on you (FR-M4).

## Where the defaults differ on purpose

These are the places where code that worked against `oidc-provider` can be refused by oidcraft.

- **PKCE.** `oidc-provider`'s default `pkce.required` function requires PKCE for public clients and
  under FAPI, and treats it as recommended for everyone else. oidcraft requires PKCE from every
  client, `S256` only. The one exemption is a confidential client the host registered with
  `requirePkce: false`, on a request that carries a `nonce` (FR-C3). A confidential client that
  sends neither PKCE nor a `nonce` will start getting errors.
- **Refresh-token rotation.** `oidc-provider`'s `rotateRefreshToken` is configurable, and its default
  is a function that decides per token. In oidcraft, every refresh token rotates, and reuse revokes
  its token family. The only exception is a FAPI 2.0 client. Neither is a setting (FR-T3).
- **Response types.** `oidc-provider` enables `code id_token` and `id_token` by default. oidcraft
  serves `code` only (FR-C1).
- **Request objects.** oidcraft accepts JAR by value and PAR, and refuses unsigned request objects
  (FR-C12).
- **Linking brokered identities.** No equivalent exists in `oidc-provider`, but if you built
  brokering on top of it, note that oidcraft links by `(provider, subject)` only, by default (FR-F5,
  NFR-S8).

The reasons for each are on the [security posture](/guide/security) page.
