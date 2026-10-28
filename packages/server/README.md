# oidcraft

An OpenID Provider library for TypeScript. You bring the server and the login screens; oidcraft
brings the protocol: authorization, tokens, sessions, logout, and signing people in through Google,
Microsoft or any other OpenID provider. One build runs on Bun, Node, Deno and Cloudflare Workers.

> **Status: early.** The OpenID Foundation conformance suite's `basic` and `config` plans pass in
> CI, which is a passing run, not a certification. No deployment has used it in production yet. See
> [PLAN.md](https://github.com/Fl0r14n/oidcraft/blob/main/PLAN.md) for exactly what that means.
- [Install](#install)
- [The smallest provider](#the-smallest-provider)
- [Your login screens](#your-login-screens)
- [Local accounts](#local-accounts)
- [Sign in with Google or Microsoft](#sign-in-with-google-or-microsoft)
- [Storage](#storage)
- [Node, Deno and Workers](#node-deno-and-workers)
- [Several issuers in one process](#several-issuers-in-one-process)
- [Before production](#before-production)
- [What it does](#what-it-does)

## Install

```sh
bun add oidcraft        # or npm install oidcraft
```

The storage adapters use your database library as an optional peer, so you install only the one you
use: `drizzle-orm`, `kysely` or `typeorm`. The core depends on `jose` and nothing else.

## The smallest provider

```ts
import { createProvider } from 'oidcraft'
import { memoryAdapter } from 'oidcraft/adapters/memory'

const adapter = await memoryAdapter({
  accounts: {
    find: async accountId => ({ accountId, claims: {} }),
    claims: async accountId => ({ name: accountId })
  }
})

await adapter.clients.upsert?.({
  clientId: 'demo',
  redirectUris: ['http://localhost:3000/callback'],
  grantTypes: ['authorization_code', 'refresh_token'],
  responseTypes: ['code'],
  scopes: ['openid', 'profile'],
  tokenEndpointAuthMethod: 'none',
  createdAt: new Date(),
  updatedAt: new Date()
})

const provider = createProvider({
  issuer: 'http://localhost:3001',
  adapter,
  interactionUrl: 'http://localhost:3001/interaction'
})

Bun.serve({ port: 3001, fetch: request => provider.handle(request) })
```

That is a real provider: discovery at `/.well-known/openid-configuration`, keys at `/jwks`, and an
authorization endpoint for the client `demo`. The test suite runs this exact block from this file.

`provider.handle` takes a `Request` and returns a `Response`. It routes the protocol endpoints itself
and answers anything else with a 404, so you serve your own pages beside it. The one page it cannot
work without is the login screen.

## Your login screens

oidcraft renders no HTML. When the authorization endpoint needs a person (to sign in, or to agree
to what an application asks for), it redirects to `interactionUrl/<id>`. Your page reads what is
being asked and answers it:

```ts
// GET /interaction/:id — show the right screen
const view = await provider.interactions.find(id)
// view.kind is 'login', 'consent' or 'logout'; view.clientId, view.scopes and view.prompt say what is asked

// POST /interaction/:id/login — once you have checked who this is
const { redirectTo, setCookie } = await provider.interactions.complete(id, {
  login: { accountId: 'ada', amr: ['pwd'] }
})
const headers = new Headers({ location: redirectTo })
if (setCookie) headers.append('set-cookie', setCookie)
return new Response(null, { status: 303, headers })

// POST /interaction/:id/consent — the person agreed (or answer { error: { error: 'access_denied' } })
await provider.interactions.complete(id, { consent: { scopes: view.scopes } })
```

After each answer the provider re-evaluates the original request and may ask again. A person who
just signed in can still be asked for consent, so one interaction can be followed by another.
Consent is remembered per application, so a returning user is not asked twice.

## Local accounts

`oidcraft/accounts` gives you usernames and passwords, hashed with argon2id, plus TOTP authenticator
apps, recovery codes, lockout after repeated failures, and password reset:

```ts
import { createProvider } from 'oidcraft'
import { createAccounts } from 'oidcraft/accounts'
import { bunPasswordHasher } from 'oidcraft/runtimes/bun' // nodePasswordHasher on Node

const accounts = createAccounts({
  adapter: storage,
  hasher: bunPasswordHasher,
  secretKey: Bun.env.TOTP_KEY as string, // generateSecretKey() makes one; it seals TOTP secrets at rest
  issuer: 'My App' // the name an authenticator app shows
})

const provider = createProvider({
  issuer: 'https://auth.example.com',
  adapter: { ...storage, accounts: accounts.store },
  interactionUrl: 'https://auth.example.com/interaction'
})

await accounts.register({ username: 'ada', password: 'correct horse battery', claims: { name: 'Ada Lovelace' } })

// in your login screen's POST handler
const result = await accounts.authenticate(username, password)
if (result.ok && !result.secondFactor) {
  await provider.interactions.complete(id, { login: { accountId: result.accountId, amr: ['pwd'] } })
}
// result.secondFactor: ask for the code, then accounts.verifySecondFactor(result.accountId, code)
```

If you already have users somewhere else, skip this entry and pass your own `accounts`: two
functions, `find(accountId)` and `claims(accountId, scopes)`, as in the smallest provider above.

## Sign in with Google or Microsoft

oidcraft can broker: your applications sign in at oidcraft, and oidcraft signs the person in at an
upstream provider. Your applications never learn the upstream exists, and you can add or swap
upstreams without touching them.

```ts
import { createProvider } from 'oidcraft'
import { createBroker, linkIdentity, localSubject, pickClaims, type UpstreamProvider } from 'oidcraft/federation'

const google: UpstreamProvider = {
  id: 'google',
  label: 'Google',
  issuer: 'https://accounts.google.com',
  clientId: Bun.env.GOOGLE_CLIENT_ID as string,
  clientSecret: Bun.env.GOOGLE_CLIENT_SECRET as string,
  scopes: ['openid', 'email', 'profile'],
  domains: ['gmail.com'], // an email at this domain goes straight to Google
  claimMapper: pickClaims() // which upstream claims to keep; without one only `sub` is trusted
}

const provider = createProvider({
  issuer: 'https://auth.example.com',
  adapter: storage, // brokering needs its `identities` store; every shipped adapter has one
  interactionUrl: 'https://auth.example.com/interaction',
  upstreams: [{ id: 'google', label: 'Google', domains: ['gmail.com'] }] // no secrets here
})

const broker = createBroker({ adapter: storage, callbackUri: 'https://auth.example.com/federation/callback', providers: [google] })

// the "Sign in with Google" button on your login screen
const { url, setCookie } = await broker.start(id, 'google', { prompt: view.prompt })
// redirect to url, setting setCookie

// GET /federation/callback
const back = await broker.complete(new URL(request.url), request.headers.get('cookie'))
const linked = await linkIdentity(storage, back.identity, {
  createAccount: async identity => localSubject(identity.provider, identity.subject)
})
if ('accountId' in linked) {
  await provider.interactions.complete(back.interactionId, {
    login: { accountId: linked.accountId, idp: back.identity.provider }
  })
}
```

Microsoft Entra ID is the same shape with `issuer: 'https://login.microsoftonline.com/<tenant>/v2.0'`.
The login screen offers the upstreams in `view.upstream`, already narrowed by the email domain or
login hint where one is known.

An upstream identity is linked to a local account by `(provider, subject)` and nothing else. Linking
by email address is not the default, because an upstream that does not verify addresses would let
anyone take over the local account with that address.

## Storage

Everything oidcraft keeps goes through an adapter. Pick the one that matches your stack:

```ts
import { memoryAdapter } from 'oidcraft/adapters/memory' // development and tests
import { drizzleAdapter } from 'oidcraft/adapters/drizzle' // Drizzle v1
import { kyselyAdapter } from 'oidcraft/adapters/kysely' // Kysely
import { typeormAdapter } from 'oidcraft/adapters/typeorm' // a TypeORM DataSource
import { redisAdapter } from 'oidcraft/adapters/redis' // any Redis client, through one command function
```

The SQL adapters ship their schema as migrations (`SQLITE_MIGRATIONS`, and `TYPEORM_SQLITE_MIGRATIONS`
for TypeORM), and you run them with your own tooling before you deploy. oidcraft never migrates on
startup, because several processes starting at once would all try. With Drizzle and SQLite on Bun:

```ts
import { Database } from 'bun:sqlite'
import { drizzle } from 'drizzle-orm/bun-sqlite'
import { drizzleAdapter, SQLITE_MIGRATIONS } from 'oidcraft/adapters/drizzle'

const sqlite = new Database('oidcraft.sqlite')
for (const statement of SQLITE_MIGRATIONS.flatMap(migration => migration.statements)) sqlite.run(statement) // once, in your migration step
const storage = drizzleAdapter({ db: drizzle({ client: sqlite }), keys })
```

Another backend needs only a `KvStore`: five methods, one of them an atomic insert. `fromKv` builds a
complete adapter from it.

## Node, Deno and Workers

`provider.handle` is the same everywhere. What differs is how a runtime tells you the client's IP
address, which oidcraft uses for rate limiting, so each runtime has a small helper:

```ts
// Bun
import { bunContext } from 'oidcraft/runtimes/bun'
Bun.serve({ fetch: (request, server) => provider.handle(request, bunContext(issuer, server)(request)) })

// Node: node:http, Express, anything with (req, res)
import { createServer } from 'node:http'
import { toNodeHandler } from 'oidcraft/runtimes/node'
createServer(toNodeHandler(provider.handle, issuer)).listen(3001)

// Deno
import { denoContext } from 'oidcraft/runtimes/deno'
Deno.serve((request, info) => provider.handle(request, denoContext(issuer)(request, info)))

// Cloudflare Workers
import { workerdContext } from 'oidcraft/runtimes/workerd'
export default { fetch: (request: Request) => provider.handle(request, workerdContext(issuer)(request, request.cf)) }
```

Behind a reverse proxy on Node, `toNodeHandler(provider.handle, issuer, { trustProxy: true })` reads
the client address from `X-Forwarded-For`. Turn that on only when the proxy is the only thing that
can reach the process. The issuer is always your configuration, never a request header.

## Several issuers in one process

Most deployments are one issuer, and need nothing from this section. A dedicated identity server
for several tenants, or for an organisation's separate apps, can run one issuer per _realm_. Each
realm is an ordinary provider with its own storage, keys, accounts and clients, built on first use:

```ts
import { createRealms } from 'oidcraft'
import { bunContext } from 'oidcraft/runtimes/bun'

const realms = createRealms({
  store: controlStorage.realms!, // where the list of realms lives
  realmOf: request => new URL(request.url).hostname.match(/^([a-z0-9-]+)\.id\.example\.com$/)?.[1],
  configure: async realm => ({
    issuer: `https://${realm.id}.id.example.com`,
    adapter: await storageFor(realm.id), // the realm's own storage and keys
    interactionUrl: `https://${realm.id}.id.example.com/interaction`
  }),
  provision: async realm => createStorageFor(realm.id), // runs before a new realm is served
  retire: async realm => dropStorageFor(realm.id) // runs after a removed realm stops being served
})

Bun.serve({
  async fetch(request, server) {
    const provider = await realms.resolve(request)
    if (!provider) return new Response('Not found', { status: 404 })
    return provider.handle(request, bunContext(provider.config.issuer, server)(request))
  }
})

await realms.management.create({ id: 'acme', displayName: 'Acme Corp' }) // also update, enable, disable, remove
```

You choose the URL scheme: a subdomain, a path or a custom domain. A request only selects a realm:
an unknown or disabled one resolves to nothing, and a realm id must be a DNS label, so a forged
`Host` header cannot create an issuer. Each realm needs its own signing keys, and two realms
sharing one are refused.

## Before production

- **Keys.** The adapters generate signing keys in memory when you pass none, and every restart signs
  everyone out. Generate a key set once, keep it as a secret, and pass it in:
  `staticKeyStore([await generateKey('ES256'), await generateKey('RS256')])`, persisted as JSON. An
  RS256 key is required: every OpenID provider must offer one.
- **https.** The issuer must be `https`, except on `localhost`.
- **Logout delivery.** oidcraft never makes outbound requests itself. Back-channel logout hands you
  the notifications through `onLogout`, and you send them.
- **Administration.** `provider.management` has functions, not routes, for clients, grants,
  sessions, keys and linked identities, with audit events through `onAudit`. Who may call them is
  your decision: oidcraft never decides who is an administrator.

## What it does

The authorization code grant with mandatory PKCE · consent remembered per application · refresh
tokens that rotate, with a replayed one revoking its grant · UserInfo · revocation and introspection ·
RP-initiated, back-channel and front-channel logout · DPoP with nonces · PAR and JAR · dynamic client
registration · the device grant · CIBA · token exchange · rich authorization requests · step-up ·
pairwise subjects · brokering with home-realm discovery · a management API.

## Why

[`oidc-provider`](https://github.com/panva/node-oidc-provider) is the reference for Node and oidcraft
owes a lot to it. It differs in three ways:

- **Runtime-portable.** The core never imports `node:http` or `node:crypto`; cryptography is WebCrypto.
- **The interaction half included.** Local accounts with TOTP, and reference screens and an admin UI
  in the repository's demo server to start from.
- **Brokering is a first-class mode.** A pure broker in front of Google or Entra, a local-account
  provider, or both at once.

## Documentation

[`ARCHITECTURE.md`](https://github.com/Fl0r14n/oidcraft/blob/main/ARCHITECTURE.md) — how it is built ·
[`REQUIREMENTS.md`](https://github.com/Fl0r14n/oidcraft/blob/main/REQUIREMENTS.md) — what it must do ·
[`PLAN.md`](https://github.com/Fl0r14n/oidcraft/blob/main/PLAN.md) — what is left

## License

MIT
