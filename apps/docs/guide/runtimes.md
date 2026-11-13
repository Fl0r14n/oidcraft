# Runtime deployment

The provider is one function, `provider.handle(request, context)`: a WHATWG `Request` and a
`RequestContext` in, a `Response` out. Nothing in its import graph touches `node:*`, and every
cryptographic operation goes through WebCrypto via `jose` (FR-R1, FR-R2). The supported hosts are
Bun ≥ 1.4, Node ≥ 24.7, Deno, and workerd-shaped runtimes such as Cloudflare Workers (FR-R3).

What differs between them is small, and lives in one entry per runtime under
`@oidcraft/provider/runtimes/*`. Each touches only its own runtime's globals and holds no protocol
logic; the build fails if `node:`, `Bun.` or `Deno.` appears outside the entry that owns it
([ARCHITECTURE.md §3.1](/reference/architecture#_3-1-request-pipeline)).

**How much of this has run where.** The OpenID Foundation conformance plans in CI run against
`apps/demo-server`, on Bun. The Node bridge is tested against a `node:http` server, but under Bun's
implementation of `node:http`, not under Node. The Deno and workerd entries are tested under Bun
with the arguments those runtimes pass; this repository does not run them on Deno or workerd. That
is also where the samples on this page stop. None of it is certified, and no deployment has used it
in production.

| runtime            | entry              | HTTP bridge     | client IP from                                  | client certificate                     | password hasher      |
| ------------------ | ------------------ | --------------- | ----------------------------------------------- | -------------------------------------- | -------------------- |
| Bun                | `runtimes/bun`     | none            | `server.requestIP(request)`                     | never (G-8)                            | `bunPasswordHasher`  |
| Node               | `runtimes/node`    | `toNodeHandler` | the socket, or `X-Forwarded-For` if you opt in  | thumbprint only, if the TLS layer verified it | `nodePasswordHasher` |
| Deno               | `runtimes/deno`    | none            | the handler's `info.remoteAddr`                 | not supplied                           | none shipped         |
| Cloudflare Workers | `runtimes/workerd` | none            | the `CF-Connecting-IP` header                   | from `request.cf`, if the edge verified it | none shipped     |

## The issuer is configuration

<<< @/samples/runtimes.test.ts#issuer{ts}

The issuer goes into every token and every discovery document, so it is never derived from the
request. A `Host` or `X-Forwarded-Host` header that could change it would let a request rewrite the
issuer of the tokens it receives (NFR-S6). No request context carries an issuer, so nothing a
request says can become one, and every runtime's test on this page sends a hostile `Host`,
`X-Forwarded-Host` and `X-Forwarded-Proto` and checks that discovery still reports the configured
issuer.

Behind a proxy that terminates TLS, the issuer is still the public `https` origin your users see,
written into your configuration.

## Why every runtime needs a context provider

Only Node needs an HTTP bridge, because only `node:http` speaks something other than
`Request`/`Response`. But what the provider needs beyond the request is not on `Request` on any
runtime, so every runtime needs a context provider (FR-R3, FR-R4):

- **`clientCertificate`**, the TLS client certificate the listener verified. The token, UserInfo,
  revocation, introspection, device authorization, CIBA and PAR endpoints read it for mTLS client
  authentication and certificate-bound tokens (FR-C4, FR-C13).
- **`clientIp`**, the peer address. `provider.handle` does not read it. The device flow's
  verification screen does, through `provider.device.find`, `resolve` and `signIn`: wrong user codes
  are limited per address (RFC 8628 §5.1), and without an address every guesser shares one wider
  bucket. Your verification page passes the context's `clientIp` to those calls, and your login
  screen to `accounts.authenticate` and `verifySecondFactor`, which count failures per address.

Nothing reads `X-Forwarded-*` on its own authority (FR-R4, NFR-S6). Where a forwarded address is
used at all, it is because you turned it on, on Node.

## Bun

`Bun.serve` takes a `Request`-to-`Response` function, so the provider mounts directly. `bunContext`
asks the server for the peer address:

<<< @/samples/runtimes.test.ts#bun{ts}

`port: 0` picks a free port, which is what the test needs; use your own.

**No mTLS on Bun.** `Bun.serve` can request a client certificate, but exposes no way to read it, so
the context never carries one. `tls_client_auth`, `self_signed_tls_client_auth` and
certificate-bound tokens are unavailable on Bun until Bun exposes the certificate (G-8). DPoP and
`private_key_jwt` cover sender-constraining and client authentication there.

## Node

`node:http` hands you `IncomingMessage` and `ServerResponse`, so `toNodeHandler` translates both
ways. It works with `node:http`, `node:https`, Express, or anything with that signature:

<<< @/samples/runtimes.test.ts#node{ts}

The issuer you pass is also the base the bridge rebuilds each request's URL from.

**Behind a reverse proxy**, `toNodeHandler(provider.handle, issuer, { trustProxy: true })` takes the
client address from `X-Forwarded-For`, and only the right-most entry, the one your proxy appended;
everything to its left is whatever the client wrote. Turn it on only when the proxy is the only
thing that can reach the process. `trustProxy` changes the client address and nothing else: the
issuer is still your configuration. The lower-level pieces are exported too: `nodeContext`,
`toRequest` and `sendResponse`.

**Node version.** Node 24.7 or later, the first with argon2 in `node:crypto`, which
`nodePasswordHasher` uses; CI imports every published entry on Node 24.7 to keep that floor true.

**mTLS on Node.** With an `https` server that requests client certificates, `nodeContext` supplies
whatever certificate the client presented — its thumbprint, its subject and issuer as RFC 4514
names, its subject alternative names, and `verified`, which is `socket.authorized`: whether the
chain checked against your listener's `ca`. Set `capabilities: { clientCertificate: true,
clientCertificateSans: true }`. What each use needs:

- `tls_client_auth` needs `verified`, and a client registers exactly one name its certificate must
  carry (RFC 8705 §2.1.2). `tls_client_auth_subject_dn` is compared as a name, not a string, so
  spacing, case and the spelling of an attribute type do not matter, the order of RDNs does. Or a
  SAN: `tls_client_auth_san_dns` case-insensitively, `_san_ip` whatever the address's spelling,
  `_san_email` with its domain case-insensitive and its local part exact, `_san_uri` exactly.
  Workers supply a certificate's subject but no SANs, so there a client registers its subject DN.
- `self_signed_tls_client_auth` and certificate-bound tokens (FR-C13) do not. They match the
  thumbprint, and the handshake already proved the client holds that certificate's key. To accept
  self-signed certificates the listener must not reject them: `requestCert: true,
  rejectUnauthorized: false`. That is safe only because `tls_client_auth` checks `verified` itself.

A certificate forwarded by a TLS-terminating proxy in a header is not read by any entry; behind one,
build the context yourself.

## Deno

`Deno.serve` passes the peer address as the handler's second argument. This is the handler you give
it, `Deno.serve(handler)`:

<<< @/samples/runtimes.test.ts#deno{ts}

The Deno entry supplies no client certificate, so the mTLS methods stay unavailable there, and no
password hasher is shipped for Deno.

## Cloudflare Workers

Workers put the peer address in `CF-Connecting-IP` and the edge's TLS client-auth result on
`request.cf`. This is the worker; export it as the module's default:

<<< @/samples/runtimes.test.ts#workerd{ts}

`IncomingCf` is the part of `request.cf` the entry reads, exported with it, as `DenoServeInfo` is
from the Deno entry. With `@cloudflare/workers-types` installed, `Request` declares `cf` itself, which is what the shorter
form in the provider guide's [Node, Deno and Workers](/guide/provider#node-deno-and-workers) section
relies on.

**mTLS on Workers.** Cloudflare verifies the certificate at the edge; the worker never sees it, only
the edge's verdict and its SHA-256 fingerprint. `workerdContext` accepts a certificate only when it
was presented and the verdict is `SUCCESS`, and derives the RFC 8705 thumbprint from that
fingerprint, with the subject and issuer DNs alongside. Anything else is no certificate.

**Storage on Workers.** No process outlives a request and there are no timers between requests,
which the core already assumes (FR-A1, NFR-P3). The storage still has to give an atomic
insert-if-absent: a Durable Object qualifies, Workers KV does not, being eventually consistent
(FR-A3). See [Storage adapters](./adapters#insert-is-the-one-hard-requirement).

No password hasher is shipped for Workers.

## mTLS: declared, not detected

Whether a client certificate can ever arrive is something you declare, as
`capabilities.clientCertificate`; no runtime entry sets it for you, and it defaults to `false`. A
provider configured with an mTLS method without it is refused at construction, not at the first
request (FR-R5, NFR-D2):

<<< @/samples/runtimes.test.ts#mtls-refused{ts}

`build()` throws a `ConfigurationError` naming `tls_client_auth`. On Node behind an `https` listener
that verifies client certificates, or on Workers with mTLS configured at the edge, declare it:

<<< @/samples/runtimes.test.ts#mtls-node{ts}

Discovery then advertises the method and `tls_client_certificate_bound_access_tokens`. Without the
capability, neither is advertised, because advertising what the runtime cannot do would be a lie
(G-8).

## Password hashers

`@oidcraft/provider/accounts` takes any `{ hash, verify }` as its `hasher` (FR-I7). Two ship, one per
runtime entry, both argon2id and both writing PHC strings, so a deployment can move between Bun and
Node without resetting every password:

<<< @/samples/runtimes.test.ts#hashers{ts}

`verified` is `[true, true]`. On Deno and Workers, bring your own `PasswordHasher`; the provider
guide's [Local accounts](/guide/provider#local-accounts) section shows where it goes. Whether
`nodePasswordHasher` works under Deno's `node:crypto` is untested.
