# oidcraft

An OpenID Provider library for TypeScript. RFC-compliant core, runtime-portable, pluggable
storage, and identity brokering as a first-class mode rather than an application concern.

One package, seven entries:

```
oidcraft                     the OP — one fetch handler, no I/O, no node:*
oidcraft/federation          the relying-party leg: brokering to upstream OPs
oidcraft/interaction         login / consent policy
oidcraft/node                node:http bridge — the only runtime that needs one
oidcraft/adapters/memory     development and tests
oidcraft/adapters/drizzle    Postgres, SQLite
oidcraft/adapters/kysely     Postgres, SQLite, MySQL
```

`drizzle-orm`, `kysely` and `openid-client` are optional peers, each confined to the entry that
owns it — importing the core pulls none of them.

```
packages/oidcraft            the package
apps/server                  reference OP: protocol + login screens + admin
apps/client                  demo relying party: Vue 3 + vue-oidc
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
