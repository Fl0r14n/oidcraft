import { defineConfig } from 'tsdown'

// Peers on @oidcraft/adapter, never on the provider: the host installs both and hands this to it
// (ARCHITECTURE.md §2.1). The only package that imports drizzle-orm.
export default defineConfig({
  entry: { index: 'src/index.ts' },
  outDir: 'dist',
  format: 'esm',
  deps: { neverBundle: ['@oidcraft/adapter', 'drizzle-orm', /^drizzle-orm\//] },
  dts: true,
  clean: true
})
