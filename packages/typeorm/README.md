# @oidcraft/typeorm

A [TypeORM](https://typeorm.io) storage adapter for `@oidcraft/provider`, over a `DataSource` on SQLite or Postgres.

```sh
bun add @oidcraft/typeorm @oidcraft/adapter typeorm
```

```ts
import { staticKeyStore } from '@oidcraft/adapter'
import { OIDCRAFT_ENTITIES, TYPEORM_SQLITE_MIGRATIONS, typeormAdapter } from '@oidcraft/typeorm'
import { DataSource } from 'typeorm'

const dataSource = await new DataSource({
  type: 'sqlite',
  database: 'oidcraft.sqlite',
  entities: OIDCRAFT_ENTITIES,
  migrations: TYPEORM_SQLITE_MIGRATIONS
}).initialize()
await dataSource.runMigrations() // once, in your migration step
const adapter = typeormAdapter({ dataSource, keys: staticKeyStore(keys) })
```

The schema ships as migrations, `SQLITE_MIGRATIONS` and `POSTGRES_MIGRATIONS` — the same tables as
the other SQL adapters, so one database works with any of them — and as TypeORM migration classes,
`TYPEORM_SQLITE_MIGRATIONS` and `TYPEORM_POSTGRES_MIGRATIONS`. You run them with your own tooling
before you deploy; the adapter never creates or alters a table at startup.

It returns a `FullAdapter`, so it satisfies every `@oidcraft/provider` entry point: brokering, local
accounts and realms included. It passes the shared suite in `@oidcraft/adapter/conformance`, on
SQLite and Postgres.

See the [storage guide](https://github.com/Fl0r14n/oidcraft/blob/main/apps/docs/guide/adapters.md).
