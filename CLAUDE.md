# oidcraft

An OpenID Provider library: RFC-compliant core, runtime-portable, pluggable storage, and identity
brokering as a first-class mode.

## Docs

**Root `ARCHITECTURE.md`, `REQUIREMENTS.md` and `PLAN.md` are the entry points** — how it is built,
what it must do, and what is left. Each is one file carrying the current answer and no history.
Read the relevant one before anything else.

- **Before implementing anything, read twice:** `REQUIREMENTS.md` for the `FR-*`/`NFR-*` the
  request is about — the actual text, not the request's paraphrase of it — and `ARCHITECTURE.md`
  for what it would touch. If a real conflict turns up, stop and say what it is; do not implement
  until it is explicitly resolved.
- **A requirement id is a citation, not a hint.** `FR-*`, `NFR-*` and `G-*` ids are stable and are
  how requirements, architecture and code refer to each other. When either cites an id, look it up;
  when writing either, cite the id rather than restating the requirement.
- `PLAN.md` is working state — tick items off and add notes as work lands. The other two change
  only when the answer changes.

## Conventions

`ARCHITECTURE.md` §9 is normative. In short:

- **No commentary in code.** One exception: a fact the code cannot state and a reader could violate
  — an invariant, a constraint, a deliberate omission. One line, citing the `FR-*`/`NFR-*` id.
- **No explicit return type where it can be inferred.**
- **No file extension on a relative import** — `from './adapter'`, never `'./adapter.js'`.
- **No `@/` alias in `apps/*`** — it resolves under `bun build` but not under `Bun.serve`'s dev
  bundler. App-internal imports are relative (ARCHITECTURE.md §1.1).
- **Server code reads `Bun.env.X`; only browser-reachable code reads `process.env.X`.** Never
  `import.meta.env`, never a destructure or indexed read. Only `OIDCRAFT_PUBLIC_*` is inlined into
  a client bundle.
- **A file using a Bun global carries `/// <reference types="bun" />` itself.**
- Formatting is settled by `biome.json` and applied by `bun run format`. Do not argue with it.

## Hard rules

These are the ones where a plausible-looking change is a security bug:

- **The core never imports `node:*`** and never reads `X-Forwarded-*` on its own authority.
  The issuer is configuration (FR-R1, FR-R4, NFR-S6).
- **A runtime global belongs to its own entry.** `node:` only in `./runtimes/node`, `Bun.` only in
  `./runtimes/bun`, `Deno.` only in `./runtimes/deno`. Only Node needs an HTTP bridge; every runtime needs a context provider,
  because client IP and the TLS client certificate are not on `Request` anywhere (ARCHITECTURE.md §3.1).
- **The core performs no I/O and holds no state across requests.** Everything goes through the
  `Adapter` (FR-A1).
- **PKCE is not optional, refresh tokens always rotate, and replaying a single-use artifact revokes
  its grant.** None of these is a configuration flag (FR-C3, FR-T3, FR-T4).
- **Account linking defaults to `(provider, subject)`.** Never add email matching as a default —
  it is an account-takeover primitive against any upstream that does not verify addresses
  (FR-F5, NFR-S8).
- **The library never decides who is an administrator** (FR-M1).

## Commands

Always `bun`, never npm/yarn/pnpm.

```sh
bun install
bun run dev              # server (3001) + client (3000)
bun run dev:server
bun run dev:client
bun run typecheck        # tsc, or vue-tsgo where there are SFCs
bun run test
bun run lint             # biome check .
bun run format           # biome check --write .
bun run conformance      # OpenID Foundation suite against apps/server
```

## Gotchas

- **One package, ten subpath entries** (`packages/oidcraft`). An optional peer belongs to exactly
  one entry; `bun run --filter=oidcraft build` runs `verify-entries.ts`, which fails the build if
  one leaks, if a core type is inlined, or if `node:` appears outside the `./runtimes/node` entry
  (ARCHITECTURE.md §2.1–2.2). Do not split this into several packages without reading §2.1.
- **There is no build step for the apps.** `bun index.html` is the client — Bun bundles Vue, compiles Tailwind
  and inlines `OIDCRAFT_PUBLIC_*` itself. The server runs from source. Do not add a bundler or a
  `dist/`; `build` scripts are typechecks.
- **Each app needs its own `bunfig.toml`.** Bun reads plugins from `[serve.static]` next to the
  served entrypoint, so the root one does not reach `apps/*`. Missing, it does not error — a `.vue`
  import resolves to a path string and the page renders blank.
- **`vue-tsc` does not run on TypeScript 7.** Packages containing `.vue` files type-check with
  `vue-tsgo`; everything else uses `tsc`. Not `tsgo` — that is the older
  `@typescript/native-preview` binary and is not what `typescript@7` installs.
- **Components: Tailwind everywhere; `@vuetify/v0` in `apps/server/src/admin` only.** The login and
  consent screens stay dependency-free on purpose (ARCHITECTURE.md §8.1).
