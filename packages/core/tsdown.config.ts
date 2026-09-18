import { defineConfig } from 'tsdown'

// One entry, one dependency. This package is the relying-party side of the protocol and is consumed
// by `oidcraft/federation` as an optional peer, so nothing it pulls in may become a transitive tax on
// a consumer who only wanted the OP (NFR-D4).
export default defineConfig({
  entry: { index: 'src/index.ts' },
  outDir: 'dist',
  format: 'esm',
  deps: { neverBundle: ['jose'] },
  dts: true,
  clean: true
})
