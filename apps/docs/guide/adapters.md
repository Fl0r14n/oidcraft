# Storage adapters

Everything the provider keeps (clients, codes and tokens, sessions, consent, keys, one-time values)
goes through an `Adapter`. The core performs no I/O of its own and holds nothing in process memory
that outlives a request, so two processes behind a load balancer behave like one (FR-A1).

There are three ways to give a provider storage:

- use a first-party adapter;
- implement a `KvStore`, five methods of which one is an atomic insert, and let `fromKv` build the
  `Adapter` from it (FR-A3);
- implement the `Adapter` yourself, store by store (FR-A2, FR-A6).

The contract is its own package, `@oidcraft/adapter`, and every type and helper on this page comes
from it. The provider depends on it and re-exports its types; a first-party adapter peers on it and
never on the provider, so the two release independently. Why it is a set of narrow stores rather than one table keyed by model name is
in [ARCHITECTURE.md §4](/reference/architecture#_4-the-adapter-layer).

## First-party adapters

| package                     | backend                                                      | single use rests on                  |
| --------------------------- | ------------------------------------------------------------ | ------------------------------------ |
| `@oidcraft/adapter/memory`  | a `Map` in this process                                      | the process being single-threaded    |
| `@oidcraft/redis`           | any Redis client, through one `send(command, args)` function | `SET NX`                             |
| `@oidcraft/drizzle`         | Drizzle v1 (`drizzle-orm@>=1.0.0-rc.5`), SQLite or Postgres  | `UPDATE … WHERE consumed_at IS NULL` |
| `@oidcraft/kysely`          | Kysely, SQLite or Postgres                                   | `UPDATE … WHERE consumed_at IS NULL` |
| `@oidcraft/typeorm`         | an initialized TypeORM `DataSource` with `OIDCRAFT_SQLITE_ENTITIES` or `OIDCRAFT_POSTGRES_ENTITIES` | `UPDATE … WHERE consumed_at IS NULL` |

How to pick:

- **Use the one for the database you already run.** Each is its own package, peering on
  `@oidcraft/adapter` and on its database library, so you install only the one you use.
- **The memory adapter is for development and tests.** Everything in it dies with the process, and
  it is correct only within one process.
- **Redis** is `fromKv` over a `KvStore` built on `SET NX` and `PX` expiry, so nothing needs
  sweeping. Its `prefix` option (default `oidcraft:`) lets one Redis hold other data, or several
  issuers.
- **The SQL adapters** use real columns and indexes for what the core looks up: `grant_id`,
  `user_code`, `expires_at`, `account_id`, the upstream session id (FR-A5). They ship their schema
  as `SQLITE_MIGRATIONS` and `POSTGRES_MIGRATIONS`, exported from each of the three packages because
  all three query the same tables (TypeORM also gets them as migration classes,
  `TYPEORM_SQLITE_MIGRATIONS` and `TYPEORM_POSTGRES_MIGRATIONS`). You run them
  with your own tooling: the library never creates or alters a table at startup (FR-A4,
  [ARCHITECTURE.md §4.2](/reference/architecture#_4-2-schema-ownership)).

Every first-party adapter returns a `FullAdapter`, so it satisfies every entry point: brokering,
local accounts and realms included. Each takes a `keys` store; the memory adapter generates one
when you pass none, and so restarts sign everyone out. The code for each, and the Drizzle-on-SQLite
setup, is in the provider guide's [Storage](/guide/provider#storage) section; persisting keys is
under [Before production](/guide/provider#before-production).

**Expired rows.** The SQL adapters filter expiry in the query, so an expired code or token is never
served whether or not it has been deleted (FR-T5). Deleting them is `prune(before, limit)`, a bounded sweep, on each store that grows:
`adapter.artifacts`, `adapter.sessions` and `adapter.replay`, where every `jti` and DPoP proof leaves
an entry. Nothing in the library calls them: the provider holds no timers (NFR-P3), so you schedule
all three. The `KvStore`-based adapters have no `prune`; their entries carry a TTL instead.

## Writing a `KvStore`

A `KvStore` is five methods over string keys and string values. `fromKv` does all the encoding,
picks every key, and derives the full `Adapter`:

<<< @/samples/adapters.test.ts#imports{ts}

<<< @/samples/adapters.test.ts#kv-store{ts}

What each method must do:

- **`find(key)`** returns the live entry, or `undefined`. An entry whose TTL has run out is absent.
- **`upsert({ key, value, ttl })`** writes unconditionally. `ttl` is in seconds; without one the
  entry does not expire.
- **`destroy(key)`** removes the entry; a missing key is not an error.
- **`insert({ key, value, ttl })`** writes **only if no live entry holds the key, atomically**, and
  resolves whether it wrote. An expired entry counts as absent: a one-time value whose window has
  lapsed may be claimed again.
- **`scan(prefix)`** yields every live entry whose key starts with `prefix`. `fromKv` destroys keys
  while it iterates (revoking a grant does exactly that), so the scan must survive it. If your
  backend can list a key twice, yield it once; if an entry vanishes between listing and reading,
  skip it. It should cost what it matches, not what the store holds: `fromKv` scans one record's
  keys on a request path. A store that keeps its keys in order has this for free. Redis does not —
  `SCAN MATCH` reads every key — so `@oidcraft/redis` keeps its own ordered index of key names.

Hand it to `fromKv` with a key store and, optionally, your accounts:

<<< @/samples/adapters.test.ts#from-kv{ts}

The test behind that sample registers a client, signs a person in, redeems the code, and then
replays it: the replay is refused with `invalid_grant` and the refresh token from the first
redemption stops working, because the replay revoked everything that code produced (FR-T4).
Revocation is a `scan` over the family's index followed by `destroy` calls, which is why `scan` is
one of the five.

A key-value store has no secondary index, so `fromKv` writes each one the protocol needs as a key
beside the record: revoking a grant or a family and every by-account lookup is a prefix scan of one record's
keys, never of a whole family of records (NFR-P1). The SQL adapters use real columns instead
(FR-A5).

### `insert` is the one hard requirement

Every single-use rule is one call to `insert`: redeeming a code or rotating a refresh token
(`consumed/<kind>/<id>`), admitting a `jti` or DPoP proof (`replay/<namespace>/<value>`), claiming a
username at sign-up, creating a realm. Single use cannot be built from a read followed by a write
(FR-A3, NFR-S4). This is what a read followed by a write looks like:

<<< @/samples/adapters.test.ts#racy-insert{ts}

Run against eight parallel callers for one key, all eight win. Through a provider, that would be
two parallel redemptions of one authorization code both receiving tokens. With the atomic `insert`
above, the test sees at most one redemption succeed: the other is a replay, which revokes what the code produced, and
refuses the first as well when it gets there before the first has finished.

What qualifies: Redis `SET NX`, a Cloudflare Durable Object, a single-process `Map`, a SQL
`INSERT` guarded by a primary key. What does not: an eventually consistent store, such as Workers
KV. It cannot back a provider (FR-A3).

## Implementing `Adapter` yourself

Do this when you have an existing schema, or when prefix scans are not acceptable. An `Adapter` is
an object of stores:

| store        | required | holds                                                                     |
| ------------ | -------- | ------------------------------------------------------------------------- |
| `clients`    | yes      | registered clients                                                        |
| `artifacts`  | yes      | codes, access and refresh tokens, device codes, PAR and CIBA requests, …  |
| `sessions`   | yes      | the person's session at the provider                                      |
| `grants`     | yes      | consent: what an account allowed a client                                 |
| `accounts`   | yes      | your users, read only                                                     |
| `keys`       | yes      | signing keys                                                              |
| `replay`     | yes      | one-time values                                                           |
| `identities` | no       | `(provider, subject) → account` links, for brokering                      |
| `credentials`| no       | passwords and second factors, for `@oidcraft/provider/accounts`           |
| `passkeys`   | no       | WebAuthn public keys, by credential id, for `@oidcraft/provider/accounts` |
| `realms`     | no       | a realm control plane's realms                                            |

An entry point that needs an optional store says so in its type: `createBroker` takes a
`BrokeringAdapter` (`identities` and `sessions.findByUpstreamSession` present), `createAccounts` a
`CredentialsAdapter` (`credentials` and `passkeys`), and a realm control plane a `RealmsAdapter`. `createProvider` takes a plain
`Adapter` and refuses `upstreams` without the brokering stores when it is constructed (NFR-D2).

Since an `Adapter` is a plain object, you can also start from `fromKv` or a first-party adapter and
replace one store:

<<< @/samples/adapters.test.ts#replace-store{ts}

That guard is atomic only because one process owns the `Map`; it shows the shape, not something to
run behind a load balancer.

### What each store must guarantee

These are the properties the first-party adapters are tested for. Each exists because the protocol
trusts the answer rather than re-checking it.

**Everywhere**

- A missing record is `undefined`, never a throw.

**`artifacts`**

- The identity is `(kind, id)`: two kinds may share an id. Store the kind as part of the key, and
  accept every kind the core writes rather than a fixed list.
- `find` never returns an expired artifact, even one not yet pruned (FR-T5).
- `consume(kind, id)` is atomic: `true` for exactly one caller, `false` when the artifact was
  already consumed, is unknown, or has expired. It marks the artifact rather than deleting it, so
  `find` still returns it with `consumedAt` set (FR-T3, FR-T4, NFR-S4).
- `upsert` never writes or clears `consumedAt`. A poll that read the artifact before it was
  redeemed and writes it back must not revive it.
- `revokeByGrantId(grantId)` removes every artifact of that grant and nothing else. Withdrawing
  consent calls it, so it has to find them all; that is an index on `grant_id`, not a JSON search
  (FR-A5).
- `revokeByFamilyId(familyId)` does the same for one family: every token descending from one
  authorization, which a replayed code or refresh token, or a revoked refresh token, ends while the
  same app on another device keeps working (FR-T3). Migration `0005_families` adds its column and
  index.
- `revokeByClientId(clientId)` and `grants.destroyByClientId(clientId)` remove what a deleted client
  held: its tokens, those of the client-credentials grant included, and the consents given to it.
- `findByUserCode` is optional; the device flow needs it (FR-C7). `prune` is optional; see above.

**`sessions`**

- `find` never returns an expired session.
- `addClient(id, clientId)` is atomic: two clients signing in through one session at once must both
  end up on the list that logout notifies (FR-C11). A session that is gone stays gone.
- `findByUpstreamSession` is optional; upstream back-channel logout needs it (FR-F8).

**`grants`**

- Found by id, and by `(accountId, clientId)`. Consent outlives the tokens issued under it (FR-I4).
- One grant per `(accountId, clientId)`. An `upsert` for a pair another id already holds writes into
  that grant, keeping its id and `createdAt`, atomically: two tabs consenting for the first time at
  once are two writes to one grant, not a second grant and not a failed insert. The SQL adapters
  resolve the conflict on the pair; `fromKv` claims the pair's key with `insert`.

**`clients`**

- `find` is required. `upsert`, `destroy` and `list` are optional: a fixed list of clients is a
  valid deployment, and dynamic registration is then refused (FR-C9).

**`accounts`**

- `find(accountId)` and `claims(accountId, scopes, claims)`. Claims are resolved on every request,
  never cached at sign-in (FR-C5). Release what the scopes release, and each claim named in
  `claims` as well: those are the ones the person consented to by name (FR-C22).

**`keys`**

- `active()` returns keys newest first. The first signing-capable key of an algorithm signs; the
  rest only verify, so a rotation never invalidates a live token (NFR-S7).

**`replay`**

- `claim(namespace, value, ttl)` is atomic: `true` for exactly one caller while the value is live,
  `false` for a replay. Once the TTL lapses the value may be claimed again (NFR-S5).

**`identities`**

- Keyed by `(provider, subject)` and nothing else (FR-F5, NFR-S8).

**`credentials`**, **`passkeys`** and **`realms`**

- `create` writes only when neither the account nor the username exists (for a passkey, the
  credential id; for a realm, the id), and does so atomically: two sign-ups racing for one name must
  not both win, and a credential id registered to one account is never moved to another (FR-I8).
- `passkeys.listForAccount(accountId)` is an indexed lookup; migration `0006_passkeys` adds the
  table and its index.

## Testing your adapter

Every first-party adapter — memory, Drizzle, Kysely, TypeORM, Redis, on SQLite and Postgres — passes
one shared suite, and so can yours. `@oidcraft/adapter/conformance` exports it as plain
checks rather than tests: `adapterConformance(create, options)` returns a list of `{ name, run }`,
where `run` resolves when the adapter keeps that guarantee and throws a `ConformanceError` naming
what it got when it does not. It imports no test runner, so it runs under `bun test`, Vitest, Jest or
`node:test` alike — wrap each check in your runner's `test`:

<<< @/samples/adapters.test.ts#conformance-import{ts}

<<< @/samples/adapters.test.ts#conformance{ts}

That is the `Map` from the top of this page, held to the same checks as the first-party adapters.
They cover each guarantee above, and race parallel callers against `consume`, `claim`, `addClient`
and the atomic `create`s. `create` is called once per check, so each runs against a fresh adapter —
give it a fresh database schema or key prefix, as the first-party suites do. The checks for
`identities`, `credentials`, `passkeys` and `realms` run only for the stores you list in `implements`: an
adapter for the core protocol alone is held to the core checks alone (FR-A6).

Run it against your real backend, with real concurrency. A suite that passes against one in-process
`Map` proves the logic; only the database proves the atomicity.
