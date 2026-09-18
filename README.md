# oidcraft

An OpenID Provider library for TypeScript. RFC-compliant core, runtime-portable, pluggable
storage, and identity brokering as a first-class mode rather than an application concern.

One package, ten entries:

```
oidcraft                     the OP — one fetch handler, no I/O, no node:*
oidcraft/federation          the relying-party leg: brokering to upstream OPs
oidcraft/interaction         login / consent policy
oidcraft/runtimes/node       node:http bridge + request context
oidcraft/runtimes/bun        request context for Bun.serve
oidcraft/runtimes/deno       request context for Deno.serve
oidcraft/runtimes/workerd    request context for Cloudflare Workers
oidcraft/adapters/memory     development and tests
oidcraft/adapters/drizzle    Postgres, SQLite
oidcraft/adapters/kysely     Postgres, SQLite, MySQL
```

`drizzle-orm` and `kysely` are optional peers, each confined to the entry that owns it — importing
the core pulls neither.

```
Only Node needs an HTTP bridge; the rest are small context providers for what `Request` does not
carry (client IP, verified TLS client certificate).

```
packages/core                the protocol. Private; compiled into whoever uses it
packages/client              the client runtime. Private; the framework bindings only
packages/vue                 published as vue-oidc
packages/react               published as react-oauth-oidc
packages/server              the package, published as `oidcraft`
apps/server                  reference OP: protocol + login screens + admin
apps/demo-vue                demo relying party: Vue 3 + vue-oidc
apps/demo-react              demo relying party: React 19 + react-oauth-oidc, with SSR
apps/demo-angular            demo relying party: Angular 22 + ngx-oauth (own install, ARCHITECTURE.md §8.4)
```

**Three root files carry the current state:** `ARCHITECTURE.md` (how it is built),
`REQUIREMENTS.md` (what it must do) and `PLAN.md` (what is left). None of them carries history.

```sh
bun install
bun run dev          # OP on 3001, demo client on 3000
bun run typecheck
bun run lint
```

This is a scaffold. The workspace, toolchain and adapter contract exist; the protocol does not yet
— see `PLAN.md`.

## License

MIT
