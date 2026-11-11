import { defineConfig } from 'tsdown'

// The contract every adapter peers on and the provider depends on; neither depends on the other, so
// a provider release no longer forces an adapter release (ARCHITECTURE.md §2.1). Each entry other
// than the root imports the root by name: a compiled-in copy of a record type is one that drifts.
const external = ['@oidcraft/adapter', 'jose']

export default defineConfig([
  {
    entry: { index: 'src/index.ts', sql: 'src/sql/index.ts' },
    outDir: 'dist',
    format: 'esm',
    deps: { neverBundle: ['jose'] },
    dts: true,
    clean: true
  },
  {
    entry: { memory: 'src/memory/index.ts' },
    outDir: 'dist',
    format: 'esm',
    deps: { neverBundle: external },
    dts: true,
    clean: false
  },
  {
    // plain checks that throw, so a third-party adapter runs them under any test runner (FR-A6)
    entry: { conformance: 'src/conformance/index.ts' },
    outDir: 'dist',
    format: 'esm',
    deps: { neverBundle: external },
    dts: true,
    clean: false
  }
])
