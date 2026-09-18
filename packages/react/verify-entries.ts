/// <reference types="bun" />
/** Checks the invariants the four build entries rely on. Every one fails silently: a leaked peer only
 * surfaces for a consumer who never installed it, a relative import across an entry boundary inlines a
 * second copy of the module rather than sharing it, and a missing `'use client'` only breaks in an app
 * with server components. Run after `build`. */
import { readFileSync } from 'node:fs'

const read = (name: string) => readFileSync(`dist/${name}`, 'utf8')
const imports = (source: string) => [...source.matchAll(/^import\s.*?from\s*["']([^"']+)["']/gm)].map(m => m[1] ?? '')
const importsPackage = (source: string, name: string) => imports(source).some(id => id === name || id.startsWith(`${name}/`))

const failures: string[] = []
const check = (ok: boolean, failure: string) => {
  if (!ok) failures.push(failure)
}

const ENTRIES = ['core', 'index', 'axios', 'component'] as const
const OWNED: Record<string, readonly string[]> = {
  axios: ['axios'],
  component: ['@mui/material', '@mui/icons-material', '@emotion/react', '@emotion/styled']
}

for (const entry of ENTRIES) {
  const js = read(`${entry}.mjs`)
  for (const [owner, peers] of Object.entries(OWNED)) {
    if (owner === entry) continue
    for (const peer of peers) {
      check(
        !importsPackage(js, peer),
        `${entry} references ${peer} — only the ${owner} entry may, or the optional peer becomes required for everyone`
      )
    }
  }
  // neither is published; a surviving import resolves to nothing once installed
  for (const internal of ['@oidcraft/core', '@oidcraft/client']) {
    check(!importsPackage(js, internal), `${entry} imports ${internal}, which is never published — it must be bundled in`)
  }
}

// The claim that earns `./core` its own entry: no React in its graph, so a server component can use it.
const core = read('core.mjs')
check(
  !importsPackage(core, 'react') && !importsPackage(core, 'react-dom'),
  'core imports react — the entry exists precisely so a server component can import it'
)
// the banner is emitted with whichever quotes the bundler normalises to
const hasUseClientBanner = (source: string) => /^["']use client["']/.test(source.trimStart())
check(!hasUseClientBanner(core), 'core carries a use client banner, which would drag every consumer of it across the boundary')

// The hooks and the MUI component are client-only; without the directive they break only in an app
// with server components, which is the worst place to find out.
for (const entry of ['index', 'component'] as const) {
  check(hasUseClientBanner(read(`${entry}.mjs`)), `${entry} is missing its 'use client' banner`)
}

// Satellites must reach the package by name so there is one copy of the store, and therefore one
// instance, at runtime.
for (const entry of ['index', 'axios', 'component'] as const) {
  // Either bundle counts. The axios adapter needs the core for types alone, which is a *stronger*
  // position — zero runtime coupling — and demanding a runtime import would forbid it.
  check(
    importsPackage(read(`${entry}.mjs`), 'react-oauth-oidc') || importsPackage(read(`${entry}.d.mts`), 'react-oauth-oidc'),
    `${entry} does not reference react-oauth-oidc by package name — it has inlined the core instead of sharing it`
  )
}

if (failures.length) {
  console.error(`✗ ${failures.length} entry invariant(s) broken:\n${failures.map(f => `  - ${f}`).join('\n')}`)
  process.exit(1)
}
console.log("✓ entry invariants hold: optional peers confined, core free of react, 'use client' where it belongs")
