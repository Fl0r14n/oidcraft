import { defineConfig } from 'tsdown'

// One package, one version, one publish — the adapter contract is the thing most likely to churn,
// and a split would make that a version matrix for every consumer (ARCHITECTURE.md §2.1).
//
// Each optional peer is confined to the single entry that imports it, which is what keeps it
// optional rather than a tax on everyone. `verify-entries.ts` asserts that after the build; nothing
// else does, and every way of breaking it fails silently.
const external = ['oidcraft', 'jose']

export default defineConfig([
  {
    entry: { index: 'src/index.ts' },
    outDir: 'dist',
    format: 'esm',
    deps: { neverBundle: ['jose'] },
    dts: true,
    clean: true
  },
  {
    // the only entry that may import openid-client
    entry: { federation: 'src/federation/index.ts' },
    outDir: 'dist',
    format: 'esm',
    deps: { neverBundle: [...external, 'openid-client'] },
    dts: true,
    clean: false
  },
  {
    entry: { interaction: 'src/interaction/index.ts', node: 'src/node/index.ts' },
    outDir: 'dist',
    format: 'esm',
    deps: { neverBundle: external },
    dts: true,
    clean: false
  },
  {
    entry: { 'adapters/memory': 'src/adapters/memory/index.ts' },
    outDir: 'dist',
    format: 'esm',
    deps: { neverBundle: external },
    dts: true,
    clean: false
  },
  {
    // the only entry that may import drizzle-orm
    entry: { 'adapters/drizzle': 'src/adapters/drizzle/index.ts' },
    outDir: 'dist',
    format: 'esm',
    deps: { neverBundle: [...external, 'drizzle-orm', /^drizzle-orm\//] },
    dts: true,
    clean: false
  },
  {
    // the only entry that may import kysely
    entry: { 'adapters/kysely': 'src/adapters/kysely/index.ts' },
    outDir: 'dist',
    format: 'esm',
    deps: { neverBundle: [...external, 'kysely'] },
    dts: true,
    clean: false
  }
])
