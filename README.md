# oidcraft

An OpenID Provider library for TypeScript, and the client libraries that sign in against it.

- **[`oidcraft`](packages/server/README.md)**: the provider. Authorization, tokens, sessions,
  logout, local accounts with TOTP, and signing people in through Google, Microsoft or any other
  OpenID provider. One build runs on Bun, Node, Deno and Cloudflare Workers. **Start with its
  [guide](packages/server/README.md).**
- **[`vue-oidc`](packages/vue/README.md)**, **`react-oauth-oidc`** and **[`ngx-oauth`](packages/angular/README.md)**:
  sign-in for Vue, React and Angular applications, against oidcraft or any OpenID provider.

> **Status: early.** The OpenID Foundation conformance suite's `basic` and `config` plans pass in CI,
> which is a passing run, not a certification. No deployment has used it in production yet.

## Try it

```sh
bun install
bun run dev     # the reference provider on :3001, a Vue application signing in against it on :3000
```

Open http://localhost:3000 and sign in as `ada`, `grace` or `admin`; the password is
`OIDCRAFT_DEMO_PASSWORD` in `.env.example`. The provider's own pages are worth a look too:

- http://localhost:3001/admin: clients, sessions, grants and keys (sign in as an account in `OIDCRAFT_ADMINS`)
- http://localhost:3001/account: an account's own password, authenticator app and recovery codes
- http://localhost:3001/device: the screen a TV or CLI sends you to

`.env.example` lists every setting, including the Google client that turns on "Sign in with Google".

## The repository

```
packages/server     oidcraft: the provider, published with thirteen entry points
packages/vue        vue-oidc
packages/react      react-oauth-oidc
packages/angular    ngx-oauth
packages/core       the protocol both sides share. Private, compiled into each package
packages/client     the browser runtime the client libraries share. Private
packages/ui         the reference screens and their design. Private, demo only
apps/demo-server    the reference provider: protocol, login screens, admin and account apps
apps/demo-vue       a Vue application signing in with vue-oidc
apps/demo-react     a React application with SSR, signing in with react-oauth-oidc
apps/demo-angular   an Angular application signing in with ngx-oauth
```

```sh
bun run verify        # what CI runs: lint, build, typecheck, tests — run it before every commit
bun run conformance   # the OpenID Foundation suite against the demo server (needs the suite running)
```

Three root files carry the current state of the project, with no history in them:
[`ARCHITECTURE.md`](ARCHITECTURE.md) (how it is built), [`REQUIREMENTS.md`](REQUIREMENTS.md) (what
it must do) and [`PLAN.md`](PLAN.md) (what is left).

## License

MIT
