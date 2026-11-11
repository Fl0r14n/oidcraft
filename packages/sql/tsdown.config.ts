import { defineConfig } from 'tsdown'

// Private. Built so each SQL adapter compiles in this dist rather than these sources: a declaration
// build reaching a sibling's sources writes stray .d.ts files beside them (ARCHITECTURE.md §2.1).
export default defineConfig({
  entry: { sqlite: 'src/sqlite.ts', postgres: 'src/postgres.ts' },
  outDir: 'dist',
  format: 'esm',
  dts: true,
  clean: true
})
