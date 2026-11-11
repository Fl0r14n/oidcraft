import { defineConfig } from 'tsdown'

// Two entries. `@oidcraft/core` and `@oidcraft/client` are dependencies and stay external, so every
// binding shares one copy of each (ARCHITECTURE.md §2.1); `@angular/core` is the one peer.
//
// This package carries no decorators — the whole binding is `InjectionToken` factories and `inject()`
// — which is what lets it build with tsdown like everything else here instead of needing ng-packagr.
// The Material login component of v8 does not share that property; see PLAN.md.
export default defineConfig([
  {
    entry: { index: 'src/index.ts' },
    outDir: 'dist',
    format: 'esm',
    deps: { neverBundle: ['jose', '@oidcraft/core', '@oidcraft/client', '@angular/core', '@oidcraft/angular/core'] },
    dts: true,
    clean: true
  },
  {
    entry: { core: 'src/core.ts' },
    outDir: 'dist',
    format: 'esm',
    deps: { neverBundle: ['jose', '@oidcraft/core', '@oidcraft/client'] },
    dts: true,
    clean: false
  }
])
