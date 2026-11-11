import { defineConfig } from 'tsdown'

// The storage contract is `@oidcraft/adapter`, a dependency; the adapters are packages of their own
// that never depend on this one (ARCHITECTURE.md §2.1). Every entry imports the root, the contract
// and the protocol by name. `verify-entries.ts` asserts that after the build; nothing else does,
// and every way of breaking it fails silently.
const external = ['@oidcraft/provider', '@oidcraft/adapter', '@oidcraft/core', 'jose']

export default defineConfig([
  {
    entry: { index: 'src/index.ts' },
    outDir: 'dist',
    format: 'esm',
    deps: { neverBundle: ['@oidcraft/adapter', '@oidcraft/core', 'jose'] },
    dts: true,
    clean: true
  },
  {
    entry: { broker: 'src/broker/index.ts' },
    outDir: 'dist',
    format: 'esm',
    deps: { neverBundle: external },
    dts: true,
    clean: false
  },
  {
    entry: { accounts: 'src/accounts/index.ts' },
    outDir: 'dist',
    format: 'esm',
    deps: { neverBundle: external },
    dts: true,
    clean: false
  },
  {
    entry: { interaction: 'src/interaction/index.ts' },
    outDir: 'dist',
    format: 'esm',
    deps: { neverBundle: external },
    dts: true,
    clean: false
  },
  {
    // one entry per runtime: each may touch only its own globals, nothing may touch another's
    entry: {
      'runtimes/node': 'src/runtimes/node/index.ts',
      'runtimes/bun': 'src/runtimes/bun/index.ts',
      'runtimes/deno': 'src/runtimes/deno/index.ts',
      'runtimes/workerd': 'src/runtimes/workerd/index.ts'
    },

    outDir: 'dist',
    format: 'esm',
    deps: { neverBundle: external },
    dts: true,
    clean: false
  }
])
