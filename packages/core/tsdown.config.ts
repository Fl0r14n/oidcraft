import { defineConfig } from 'tsdown'

// Two entries in one build, so the protocol code they share becomes a chunk rather than two copies.
// `.` is universal and is what `oidcraft/federation` uses; `./client` is stateful and browser-facing,
// and the server must never pull it in (ARCHITECTURE.md §2.1).
export default defineConfig({
  entry: { index: 'src/index.ts', client: 'src/client/index.ts' },
  outDir: 'dist',
  format: 'esm',
  deps: { neverBundle: ['jose'] },
  dts: true,
  clean: true
})
