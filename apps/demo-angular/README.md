# @oidcraft/demo-angular

The Angular relying party, against the provider in `apps/server`.

**This app is a toolchain island, on purpose.** `@angular/compiler-cli` requires
`typescript >=6.0 <6.1` and the rest of this workspace is on 7, so it carries its own nested
TypeScript, its own `tsconfig.json` that does not extend `tsconfig.base.json`, and the Angular CLI
instead of Bun or tsdown. Nothing else here needs any of that — `packages/angular` itself builds with
tsdown on TypeScript 7, because it contains no decorators (PLAN.md).

```sh
bun run --filter=@oidcraft/server-app dev    # the provider, on :3001
bun run --filter=@oidcraft/demo-angular dev  # this app, on :3003
```

It is written against the `OAUTH` token rather than `ngx-oauth/component`, which v9 does not ship.
That makes it the better demo: the signals it reads are the whole public surface.
