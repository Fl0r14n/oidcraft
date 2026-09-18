import { defineConfig } from 'tsdown'

// One entry, one dependency. This is the protocol and nothing else: it runs in any runtime, holds no
// state, and is what `oidcraft`'s federation leg compiles in. The stateful browser-facing half is
// `@oidcraft/client`, which builds on this (ARCHITECTURE.md §2.1).
export default defineConfig({
  entry: { index: 'src/index.ts' },
  outDir: 'dist',
  format: 'esm',
  deps: { neverBundle: ['jose'] },
  dts: true,
  clean: true
})
