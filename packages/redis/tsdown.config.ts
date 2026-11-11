import { defineConfig } from 'tsdown'

// Peers on @oidcraft/adapter, never on the provider: the host installs both and hands this to it
// (ARCHITECTURE.md §2.1). Takes a command function, so it imports no Redis client and no runtime.
export default defineConfig({
  entry: { index: 'src/index.ts' },
  outDir: 'dist',
  format: 'esm',
  deps: { neverBundle: ['@oidcraft/adapter'] },
  dts: true,
  clean: true
})
