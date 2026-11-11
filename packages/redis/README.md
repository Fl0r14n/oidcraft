# @oidcraft/redis

A Redis storage adapter for `@oidcraft/provider`, through one command function you supply, so it works
with any client on any runtime and imports none itself.

```sh
bun add @oidcraft/redis @oidcraft/adapter
```

```ts
import { staticKeyStore } from '@oidcraft/adapter'
import { redisAdapter } from '@oidcraft/redis'
import { RedisClient } from 'bun'

const client = new RedisClient(url)
const adapter = redisAdapter((command, args) => client.send(command, args), { keys: staticKeyStore(keys) })
// ioredis:    (command, args) => redis.call(command, ...args)
// node-redis: (command, args) => client.sendCommand([command, ...args])
```

It is `fromKv` over a `KvStore` built on `SET NX` and `PX` expiry, so single use holds across every
process sharing the instance and nothing needs sweeping. `prefix` (default `oidcraft:`) lets one
Redis hold other data, or several issuers.

It returns a `FullAdapter`, so it satisfies every `@oidcraft/provider` entry point, and passes the
shared suite in `@oidcraft/adapter/conformance`.

See the [storage guide](https://github.com/Fl0r14n/oidcraft/blob/main/apps/docs/guide/adapters.md).
