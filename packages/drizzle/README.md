# @oidcraft/drizzle

A [Drizzle](https://orm.drizzle.team) v1 storage adapter for `@oidcraft/provider`, on SQLite, Postgres, MySQL or MariaDB.

```sh
bun add @oidcraft/drizzle @oidcraft/adapter drizzle-orm
```

```ts
import { Database } from 'bun:sqlite'
import { staticKeyStore } from '@oidcraft/adapter'
import { drizzleAdapter, SQLITE_MIGRATIONS } from '@oidcraft/drizzle'
import { createProvider } from '@oidcraft/provider'
import { drizzle } from 'drizzle-orm/bun-sqlite'

const sqlite = new Database('oidcraft.sqlite')
for (const statement of SQLITE_MIGRATIONS.flatMap(migration => migration.statements)) sqlite.run(statement) // once, in your migration step
const adapter = drizzleAdapter({ db: drizzle({ client: sqlite }), keys: staticKeyStore(keys) })
const provider = createProvider({ issuer, adapter, interactionUrl })
```

On Postgres, pass `tables: postgresTables(schema?)` beside a Postgres `db`; the schema is where a realm's
tables live. On MySQL or MariaDB, pass `tables: mysqlTables(database?)` beside a `drizzle-orm/mysql2`
`db`: the two are one dialect, and the adapter writes only what both servers accept.

The schema ships as migrations, `SQLITE_MIGRATIONS`, `POSTGRES_MIGRATIONS` and `MYSQL_MIGRATIONS` — the same tables as
the other SQL adapters, so one database works with any of them — which you run with your own tooling
before you deploy. The adapter never creates or alters a table at startup.

It returns a `FullAdapter`, so it satisfies every `@oidcraft/provider` entry point: brokering, local
accounts and realms included. It passes the shared suite in `@oidcraft/adapter/conformance`, on
SQLite, Postgres, MySQL 8.4 and MariaDB 11.

See the [storage guide](https://github.com/Fl0r14n/oidcraft/blob/main/apps/docs/guide/adapters.md).
