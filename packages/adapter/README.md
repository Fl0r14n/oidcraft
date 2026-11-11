# @oidcraft/adapter

The storage contract of [`@oidcraft/provider`](https://www.npmjs.com/package/@oidcraft/provider): what an
adapter implements, the records it holds, and what every adapter is tested against. The provider
depends on it; every adapter peers on it and never on the provider, so a provider release does not
force an adapter release.

```sh
bun add @oidcraft/adapter
```

| entry                           | what                                                                                                             |
| ------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `@oidcraft/adapter`             | `Adapter` and its stores, the records (`Client`, `Session`, `Grant`…), `fromKv`, `staticKeyStore`, `generateKey` |
| `@oidcraft/adapter/memory`      | `memoryAdapter`, for development and tests: everything dies with the process                                     |
| `@oidcraft/adapter/conformance` | `adapterConformance`, the shared suite as plain checks, for any test runner                                      |

For a real database: [`@oidcraft/drizzle`](https://www.npmjs.com/package/@oidcraft/drizzle),
[`@oidcraft/kysely`](https://www.npmjs.com/package/@oidcraft/kysely),
[`@oidcraft/typeorm`](https://www.npmjs.com/package/@oidcraft/typeorm) or
[`@oidcraft/redis`](https://www.npmjs.com/package/@oidcraft/redis).

A new backend needs only a `KvStore`: five methods, one of them an atomic insert, and `fromKv` builds a
complete adapter from it. Writing one, and holding it to the suite, is in the
[storage guide](https://github.com/Fl0r14n/oidcraft/blob/main/apps/docs/guide/adapters.md).
