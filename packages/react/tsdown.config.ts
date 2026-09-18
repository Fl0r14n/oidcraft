import { defineConfig } from 'tsdown'

// Four entries, each a separate build so its directive and its externals are its own:
//
//   core       the protocol and client runtime, re-exported from @oidcraft/core, which is compiled in
//              because that package is never published (ARCHITECTURE.md §2.1). No React in its graph,
//              so no 'use client'.
//   index      the React bindings plus a re-export of core. 'use client', which is exactly why core
//              needs an entry of its own — a server component importing createOAuth must not be
//              dragged across the client boundary.
//   axios      the optional axios adapter. The only entry that imports axios.
//   component  the optional MUI UI. Keeps @mui out of an app that only wants hooks.
//
// Each build keeps the others external by package name, so there is one copy of each at runtime. A
// relative import across an entry boundary silently inlines a second.
const USE_CLIENT = { banner: "'use client'" }

export default defineConfig([
  {
    entry: { core: 'src/core.ts' },
    outDir: 'dist',
    format: 'esm',
    deps: { neverBundle: ['axios'] },
    dts: true,
    clean: true
  },
  {
    entry: ['src/index.ts'],
    outDir: 'dist',
    format: 'esm',
    deps: { neverBundle: ['react-oauth-oidc/core', 'react', 'react-dom', 'axios'] },
    outputOptions: USE_CLIENT,
    dts: true,
    clean: false
  },
  {
    // the only entry that imports axios, which is why the dependency is optional
    entry: { axios: 'src/axios/index.ts' },
    outDir: 'dist',
    format: 'esm',
    deps: { neverBundle: ['react-oauth-oidc/core', 'axios'] },
    dts: true,
    clean: false
  },
  {
    entry: { component: 'src/component/index.ts' },
    outDir: 'dist',
    format: 'esm',
    deps: {
      neverBundle: ['react-oauth-oidc', 'react-oauth-oidc/core', 'react', 'react-dom', 'axios', '@mui/material', /^@mui\//, /^@emotion\//]
    },
    outputOptions: USE_CLIENT,
    dts: true,
    clean: false
  }
])
