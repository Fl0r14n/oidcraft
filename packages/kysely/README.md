# @oidcraft/kysely

A [Kysely](https://kysely.dev) storage adapter for `@oidcraft/provider`, on SQLite or Postgres.

```sh
bun add @oidcraft/kysely @oidcraft/adapter kysely
```

```ts
import { staticKeyStore } from '@oidcraft/adapter'
import { kyselyAdapter } from '@oidcraft/kysely'

const adapter = kyselyAdapter({ db, keys: staticKeyStore(keys) }) // db: Kysely<OidcraftDatabase>
```

Table names are unqualified, so pick a Postgres schema with the search path or `db.withSchema(...)`.

The schema ships as migrations, `SQLITE_MIGRATIONS` and `POSTGRES_MIGRATIONS` (re-exported from
`@oidcraft/adapter/sql`), which you run with your own tooling before you deploy. The adapter never
creates or alters a table at startup.

It returns a `FullAdapter`, so it satisfies every `@oidcraft/provider` entry point: brokering, local
accounts and realms included. It passes the shared suite in `@oidcraft/adapter/conformance`, on
SQLite and Postgres.

See the [storage guide](https://github.com/Fl0r14n/oidcraft/blob/main/apps/docs/guide/adapters.md).
