# @oidcraft/typeorm

A [TypeORM](https://typeorm.io) storage adapter for `@oidcraft/provider`, over a `DataSource` on SQLite, Postgres, MySQL or MariaDB.

```sh
bun add @oidcraft/typeorm @oidcraft/adapter typeorm
```

```ts
import { staticKeyStore } from '@oidcraft/adapter'
import { OIDCRAFT_SQLITE_ENTITIES, TYPEORM_SQLITE_MIGRATIONS, typeormAdapter } from '@oidcraft/typeorm'
import { DataSource } from 'typeorm'

const dataSource = await new DataSource({
  type: 'sqlite',
  database: 'oidcraft.sqlite',
  entities: OIDCRAFT_SQLITE_ENTITIES,
  migrations: TYPEORM_SQLITE_MIGRATIONS
}).initialize()
await dataSource.runMigrations() // once, in your migration step
const adapter = typeormAdapter({ dataSource, keys: staticKeyStore(keys) })
```

The schema ships as migrations, `SQLITE_MIGRATIONS`, `POSTGRES_MIGRATIONS` and `MYSQL_MIGRATIONS` —
the same tables as the other SQL adapters, so one database works with any of them — and as TypeORM
migration classes, `TYPEORM_SQLITE_MIGRATIONS`, `TYPEORM_POSTGRES_MIGRATIONS` and
`TYPEORM_MYSQL_MIGRATIONS`. The entities come in the same three sets, `OIDCRAFT_SQLITE_ENTITIES`,
`OIDCRAFT_POSTGRES_ENTITIES` and `OIDCRAFT_MYSQL_ENTITIES`: register the one that matches the
migrations, or TypeORM's schema builder finds every table's columns of the wrong type. MySQL and
MariaDB are one dialect: the MySQL set serves a `DataSource` of type `mysql` or `mariadb`. You run them with your own tooling
before you deploy; the adapter never creates or alters a table at startup.

It returns a `FullAdapter`, so it satisfies every `@oidcraft/provider` entry point: brokering, local
accounts and realms included. It passes the shared suite in `@oidcraft/adapter/conformance`, on
SQLite, Postgres, MySQL 8.4 and MariaDB 11.

See the [storage guide](https://github.com/Fl0r14n/oidcraft/blob/main/apps/docs/guide/adapters.md).
