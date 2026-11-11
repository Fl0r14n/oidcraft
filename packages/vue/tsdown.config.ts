import { defineConfig } from 'tsdown'
import vue from 'unplugin-vue/rolldown'

// `@oidcraft/core` and `@oidcraft/client` are dependencies and stay external, so the bindings share one
// copy of each (ARCHITECTURE.md §2.1).
export default defineConfig([
  {
    // one build for both, so the shared core becomes a chunk rather than a copy in each
    entry: { index: 'src/index.ts', core: 'src/core.ts' },
    outDir: 'dist',
    format: 'esm',
    deps: { neverBundle: ['jose', '@oidcraft/core', '@oidcraft/client', 'vue'] },
    dts: true,
    clean: true
  },
  {
    // the only entry that imports axios, which is what makes the dependency optional
    entry: { axios: 'src/axios/index.ts' },
    outDir: 'dist',
    format: 'esm',
    deps: { neverBundle: ['jose', '@oidcraft/core', '@oidcraft/client', '@oidcraft/vue', 'vue', 'axios'] },
    dts: true,
    clean: false
  },
  {
    // the only entry that imports vuetify, keeping it out of an app that wants composables alone
    entry: { component: 'src/component/index.ts' },
    outDir: 'dist',
    format: 'esm',
    deps: { neverBundle: ['jose', '@oidcraft/core', '@oidcraft/client', '@oidcraft/vue', 'vue', 'vuetify', /^vuetify\//, '@mdi/js'] },
    plugins: [vue()],
    css: { fileName: 'component.css' },
    dts: true,
    clean: false
  }
])
