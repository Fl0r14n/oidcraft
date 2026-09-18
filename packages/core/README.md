# @oidcraft/core — not published

**Nothing on npm resolves this name.** It is compiled into whichever package uses it, so nothing
outside this workspace may depend on it (ARCHITECTURE.md §2.1). Publishing it is a deferred
decision, not a closed one — `PLAN.md` records what would reopen it.

The relying-party half of OpenID Connect: discovery, PKCE, the authorization round trip and ID token
verification. `jose` is its only dependency, it touches no framework, and it performs no redirect and
writes to no storage — where the handoff lives is the caller's decision, and that decision is the one
thing that differs between a browser app and a confidential client.

Its consumers are `oidcraft/federation`, which is a relying party at every upstream it brokers to,
and this workspace's framework client libraries — `vue-oidc`, and the Angular and React ones to come
— which publish under their own names. One implementation of the client leg, not four.

## The round trip

```ts
import { applyDiscovery, beginAuthorization, completeAuthorization, createDiscovery } from '@oidcraft/core'

const discover = createDiscovery()
const base = { issuerPath: 'https://accounts.google.com', clientId: '…', scope: 'openid email', pkce: true }
const config = applyDiscovery(base, await discover(base))

// send the user to `url`, keep `handoff` until they come back
const { url, handoff } = await beginAuthorization(config, {
  redirectUri: 'https://app.example/cb',
  responseType: 'code'
})

// on the callback, with the handoff you kept
const token = await completeAuthorization(config, window.location, handoff)
```

`handoff` carries the `state`, `nonce` and PKCE verifier and nothing else. It is passed back in
rather than looked up, which is what makes `completeAuthorization` safe to run concurrently — a
process-wide holder is another user's nonce.

## What it checks, and what it leaves to you

Checked, without a flag to turn any of it off:

| | |
| --- | --- |
| **Every endpoint is https** | A code or a secret on the wire in clear is a code or a secret someone already has. `allowInsecure` exists for development and is the only way to say it — `localhost` is not exempt. |
| **The discovery document asserts its own issuer** | OIDC Discovery 1.0 §4.3. Without it, a host that will serve someone else's document hands over that issuer's endpoints. Entra's `{tenantid}` template is the one documented exception. |
| **`iss` on the authorization response** | RFC 9207 §2.4, the mix-up defence. A provider that advertises `authorization_response_iss_parameter_supported` has promised to send it, so from that provider its absence is a failure too. |
| **`state`, `nonce`, `aud` and `azp`** | RFC 6749 §10.12 and OIDC Core §3.1.3.7, including the rule that more than one audience requires `azp`. |

Left to you, deliberately: where the handoff is stored, when to refresh, and what a token means to
your application. None of those have one right answer, and a library that picks one stops being
usable in the case it did not pick.

## Failure

A request that does not come back returns `undefined`, and a protocol failure comes back as a token
carrying `error`. A **misconfiguration** — an `http` endpoint, a document asserting the wrong issuer
— throws `InsecureEndpointError` or `IssuerMismatchError` instead. The split is on purpose: the first
two are the network's answer and the third is yours, and reporting a misconfiguration as an outage
sends you looking in the wrong place.

## Client authentication

`tokenAuthMethod` picks how credentials reach the token endpoint: `client_secret_post` (the body, the
default, and what most providers accept), `client_secret_basic` (the header, which some providers
require), or `none` for a public client. The Basic variant form-urlencodes each half before the
base64, per RFC 6749 §2.3.1 — which is the difference between working and not for any secret
containing `/`, `+`, `:` or a space.

