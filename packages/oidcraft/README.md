# oidcraft

An OpenID Provider library for TypeScript. RFC-compliant core, runtime-portable, pluggable storage,
and identity brokering as a first-class mode rather than an application concern.

> **Status: scaffold.** The package structure, build and adapter contract exist; the protocol does
> not yet. See [PLAN.md](https://github.com/Fl0r14n/oidcraft/blob/main/PLAN.md).

## Why

[`oidc-provider`](https://github.com/panva/node-oidc-provider) is the reference for Node and this
owes a lot to it. oidcraft differs in three ways:

- **Runtime-portable.** One build runs on Bun, Node, Deno and workerd. The core never imports
  `node:http` or `node:crypto` — cryptography goes through WebCrypto.
- **Batteries included for the interaction half.** Login, consent and an admin surface ship with it,
  closer to what Django's oauth-toolkit gives a Django project.
- **Federation is a first-class mode.** A deployment can be a pure broker in front of Entra, Google
  or any OIDC provider, a local-account OP, or both at once.

## Entries

```ts
import { ... } from 'oidcraft'                    // the OP — fetch in, fetch out, no I/O
import { ... } from 'oidcraft/federation'         // brokering to upstream providers
import { ... } from 'oidcraft/interaction'        // login / consent policy

import { ... } from 'oidcraft/runtimes/node'      // node:http bridge + request context
import { ... } from 'oidcraft/runtimes/bun'       // request context for Bun.serve
import { ... } from 'oidcraft/runtimes/deno'      // request context for Deno.serve
import { ... } from 'oidcraft/runtimes/workerd'   // request context for Cloudflare Workers

import { ... } from 'oidcraft/adapters/memory'    // development and tests
import { ... } from 'oidcraft/adapters/drizzle'   // Postgres, SQLite
import { ... } from 'oidcraft/adapters/kysely'    // Postgres, SQLite, MySQL
```

`drizzle-orm`, `kysely` and `openid-client` are **optional** peer dependencies, each confined to the
entry that uses it — installing oidcraft pulls none of them.

Only Node needs an HTTP bridge; Bun, Deno and workerd take the core's handler directly. Every
runtime needs a context provider, because the client IP and the verified TLS client certificate are
not carried by `Request` anywhere.

## Documentation

[`ARCHITECTURE.md`](https://github.com/Fl0r14n/oidcraft/blob/main/ARCHITECTURE.md) — how it is built ·
[`REQUIREMENTS.md`](https://github.com/Fl0r14n/oidcraft/blob/main/REQUIREMENTS.md) — what it must do ·
[`PLAN.md`](https://github.com/Fl0r14n/oidcraft/blob/main/PLAN.md) — what is left

## License

MIT
