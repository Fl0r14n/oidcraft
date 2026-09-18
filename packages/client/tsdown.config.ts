import { defineConfig } from 'tsdown'

// `@oidcraft/core` stays external here even though neither package is published. Bundling it would
// put a second copy of every protocol type in this package's declarations, and a binding importing
// `OAuthFunctions` from one and receiving the other gets "cannot be named" at its own dts emit.
// The published package is where both get compiled in (ARCHITECTURE.md §2.1).
export default defineConfig({
  entry: { index: 'src/index.ts' },
  outDir: 'dist',
  format: 'esm',
  deps: { neverBundle: ['jose', '@oidcraft/core'] },
  dts: true,
  clean: true
})
