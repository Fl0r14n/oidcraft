import { defineConfig } from 'tsdown'
import vue from 'unplugin-vue/rolldown'

// `@oidcraft/core` is never in a neverBundle list: it is a workspace package that is not published,
// so it is compiled in and a consumer resolves `vue` and nothing else (ARCHITECTURE.md §2.1).
export default defineConfig([
  {
    // one build for both, so the shared core becomes a chunk rather than a copy in each
    entry: { index: 'src/index.ts', core: 'src/core.ts' },
    outDir: 'dist',
    format: 'esm',
    deps: { neverBundle: ['vue'] },
    dts: true,
    clean: true
  },
  {
    // the only entry that imports axios, which is what makes the dependency optional
    entry: { axios: 'src/axios/index.ts' },
    outDir: 'dist',
    format: 'esm',
    deps: { neverBundle: ['vue-oidc', 'vue', 'axios'] },
    dts: true,
    clean: false
  },
  {
    // the only entry that imports vuetify, keeping it out of an app that wants composables alone
    entry: { component: 'src/component/index.ts' },
    outDir: 'dist',
    format: 'esm',
    deps: { neverBundle: ['vue-oidc', 'vue', 'vuetify', /^vuetify\//, '@mdi/js'] },
    plugins: [vue()],
    css: { fileName: 'component.css' },
    dts: true,
    clean: false
  }
])
