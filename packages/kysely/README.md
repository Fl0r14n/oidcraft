# @oidcraft/kysely

A [Kysely](https://kysely.dev) storage adapter for `@oidcraft/provider`, on SQLite, Postgres, MySQL or MariaDB.

```sh
bun add @oidcraft/kysely @oidcraft/adapter kysely
```

```ts
import { staticKeyStore } from '@oidcraft/adapter'
import { kyselyAdapter } from '@oidcraft/kysely'

const adapter = kyselyAdapter({ db, keys: staticKeyStore(keys) }) // db: Kysely<OidcraftDatabase>
```

Table names are unqualified, so pick a Postgres schema with the search path or `db.withSchema(...)`,
and a MySQL database with the connection's or `db.withSchema(...)`. MySQL and MariaDB are one dialect:
build `db` with Kysely's `MysqlDialect` over `mysql2`, and the adapter writes only what both servers
accept.

The schema ships as migrations, `SQLITE_MIGRATIONS`, `POSTGRES_MIGRATIONS` and `MYSQL_MIGRATIONS` — the same tables as
the other SQL adapters, so one database works with any of them — which you run with your own tooling
before you deploy. The adapter never creates or alters a table at startup.

It returns a `FullAdapter`, so it satisfies every `@oidcraft/provider` entry point: brokering, local
accounts and realms included. It passes the shared suite in `@oidcraft/adapter/conformance`, on
SQLite, Postgres, MySQL 8.4 and MariaDB 11.

See the [storage guide](https://github.com/Fl0r14n/oidcraft/blob/main/apps/docs/guide/adapters.md).
