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

TypeORM also gets them as migration classes, `TYPEORM_SQLITE_MIGRATIONS` and `TYPEORM_POSTGRES_MIGRATIONS`.

The schema ships as migrations, `SQLITE_MIGRATIONS` and `POSTGRES_MIGRATIONS` (re-exported from
`@oidcraft/adapter/sql`), which you run with your own tooling before you deploy. The adapter never
creates or alters a table at startup.

It returns a `FullAdapter`, so it satisfies every `@oidcraft/provider` entry point: brokering, local
accounts and realms included. It passes the shared suite in `@oidcraft/adapter/conformance`, on
SQLite and Postgres.

See the [storage guide](https://github.com/Fl0r14n/oidcraft/blob/main/apps/docs/guide/adapters.md).
