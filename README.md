# oidcraft

[![ci](https://github.com/Fl0r14n/oidcraft/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Fl0r14n/oidcraft/actions/workflows/ci.yml)
[![docs](https://img.shields.io/badge/docs-fl0r14n.github.io%2Foidcraft-blue)](https://fl0r14n.github.io/oidcraft/)
[![npm](https://img.shields.io/npm/v/@oidcraft/provider?label=%40oidcraft%2Fprovider)](https://www.npmjs.com/package/@oidcraft/provider)
[![npm](https://img.shields.io/npm/v/@oidcraft/vue?label=%40oidcraft%2Fvue)](https://www.npmjs.com/package/@oidcraft/vue)
[![npm](https://img.shields.io/npm/v/@oidcraft/react?label=%40oidcraft%2Freact)](https://www.npmjs.com/package/@oidcraft/react)
[![npm](https://img.shields.io/npm/v/@oidcraft/angular?label=%40oidcraft%2Fangular)](https://www.npmjs.com/package/@oidcraft/angular)

An OpenID Provider library for TypeScript, and the client libraries that sign in against it.
The documentation is at **[fl0r14n.github.io/oidcraft](https://fl0r14n.github.io/oidcraft/)**.

- **[`@oidcraft/provider`](packages/provider/README.md)**: the provider. Authorization, tokens, sessions,
  logout, local accounts with passwords, passkeys and TOTP, and signing people in through Google,
  Microsoft or any other OpenID provider. One build runs on Bun, Node, Deno and Cloudflare Workers.
  **Start with its [guide](packages/provider/README.md).**
- **[`@oidcraft/adapter`](packages/adapter/README.md)**: its storage contract and an in-memory adapter,
  with [`@oidcraft/drizzle`](packages/drizzle/README.md), [`@oidcraft/kysely`](packages/kysely/README.md),
  [`@oidcraft/typeorm`](packages/typeorm/README.md) for SQLite, Postgres, MySQL and MariaDB, and
  [`@oidcraft/redis`](packages/redis/README.md) for Redis.
- **[`@oidcraft/vue`](packages/vue/README.md)**, **[`@oidcraft/react`](packages/react/README.md)** and **[`@oidcraft/angular`](packages/angular/README.md)**:
  sign-in for Vue, React and Angular applications, against oidcraft or any OpenID provider. They
  continue `vue-oidc`, `react-oauth-oidc` and `ngx-oauth`.
- **[`@oidcraft/core`](packages/core/README.md)** and **[`@oidcraft/client`](packages/client/README.md)**:
  the OpenID Connect client those are built on, for a framework without a binding here.

> **Status: early.** The OpenID Foundation conformance suite's `basic`, `config` and FAPI 2.0 plans
> pass in CI, which is a passing run, not a certification. No deployment has used it in production yet.
>
> **Security:** `@oidcraft/provider` 0.3.0 and earlier have a session takeover; use 0.4.0 or later.
> Report a vulnerability privately, as [`SECURITY.md`](SECURITY.md) describes, never in a public issue.

## Install

```sh
bun add @oidcraft/provider @oidcraft/adapter   # the provider, or npm install
bun add @oidcraft/drizzle drizzle-orm          # a database: or @oidcraft/kysely, @oidcraft/typeorm, @oidcraft/redis
bun add @oidcraft/vue                          # signing in from an application: or @oidcraft/react, @oidcraft/angular
```

The packages run on Node 24.7 or later, Bun, Deno and Cloudflare Workers. The
[provider's guide](packages/provider/README.md) goes on from here.

## Try it

With Bun 1.4.4 or later:

```sh
bun install
bun run dev     # the reference provider on :3001, a Vue application signing in against it on :3000
```

Open http://localhost:3000 and sign in as `ada`, `grace` or `admin`; the password is
`OIDCRAFT_DEMO_PASSWORD` in `.env.example`. The provider's own pages are worth a look too:

- http://localhost:3001/admin: clients, sessions, grants and keys (sign in as an account in `OIDCRAFT_ADMINS`)
- http://localhost:3001/account: an account's own password, passkeys, authenticator app and recovery codes
- http://localhost:3001/device: the screen a TV or CLI sends you to

`.env.example` lists every setting, including the Google client that turns on "Sign in with Google".

## The repository

```
packages/provider   @oidcraft/provider: the provider, published with eight entry points
packages/adapter    @oidcraft/adapter: the storage contract, fromKv, the memory adapter, the conformance suite
packages/drizzle    @oidcraft/drizzle, packages/kysely, packages/typeorm, packages/redis: one adapter each
packages/vue        @oidcraft/vue, which continues vue-oidc
packages/react      @oidcraft/react, which continues react-oauth-oidc
packages/angular    @oidcraft/angular, which continues ngx-oauth
packages/core       @oidcraft/core: the protocol both sides share
packages/client     @oidcraft/client: the browser runtime the client libraries share
packages/ui         the reference screens and their design. Private, demo only
packages/sql        the SQL schema the SQL adapters share, compiled into each. Private
apps/demo-server    the reference provider: protocol, login screens, admin and account apps
apps/demo-vue       a Vue application signing in with @oidcraft/vue
apps/demo-react     a React application with SSR, signing in with @oidcraft/react
apps/demo-angular   an Angular application signing in with @oidcraft/angular
```

```sh
bun run verify        # what CI runs: lint, build, typecheck, tests — run it before every commit
bun run smoke         # the demo apps clicked through in a headless browser
bun run conformance   # the OpenID Foundation suite against the demo server (needs the suite running)
```

Three root files carry the current state of the project, with no history in them:
[`ARCHITECTURE.md`](ARCHITECTURE.md) (how it is built), [`REQUIREMENTS.md`](REQUIREMENTS.md) (what
it must do) and [`PLAN.md`](PLAN.md) (what is left).

## License

MIT
