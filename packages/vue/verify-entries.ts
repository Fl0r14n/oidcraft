/// <reference types="bun" />
/** Checks the invariants the build entries rely on. Every one of them fails silently: axios leaking
 * into the root only shows up as a resolution error in a consumer who never installed it, and a
 * relative import across an entry boundary inlines a second copy of `oauthKey`, after which every
 * composable in that entry resolves nothing. Run after `build`. */
import { readFileSync } from 'node:fs'

const read = (name: string) => readFileSync(`dist/${name}`, 'utf8')
const imports = (source: string) => [...source.matchAll(/^import\s.*?from\s*["']([^"']+)["']/gm)].map(m => m[1] ?? '')
const importsPackage = (source: string, name: string) => imports(source).some(id => id === name || id.startsWith(`${name}/`))

const failures: string[] = []
const check = (ok: boolean, failure: string) => {
  if (!ok) failures.push(failure)
}

const ENTRIES = ['index', 'core', 'axios', 'component'] as const

// An optional peer stays optional only while the single entry that owns it is the only one importing it.
const OWNED: Record<string, readonly string[]> = {
  axios: ['axios'],
  component: ['vuetify', '@mdi/js']
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
  // `@oidcraft/core` is not published; a surviving import resolves to nothing once installed
  check(!importsPackage(js, '@oidcraft/core'), `${entry} imports @oidcraft/core, which is never published — it must be bundled in`)
}

// The satellite entries must reach the root by package name. A relative import would inline a second
// `oauthKey` symbol, and `useOAuthHttp()` would then never find what `app.use()` provided.
for (const entry of ['axios', 'component'] as const) {
  check(
    importsPackage(read(`${entry}.mjs`), 'vue-oidc'),
    `${entry} does not import vue-oidc by package name — it has inlined the root instead of sharing its injection keys`
  )
}

// The claim that made `./core` worth keeping: it is the protocol, and a request handler or a worker
// can import it without pulling a UI framework in.
check(!importsPackage(read('core.mjs'), 'vue'), 'core imports vue — the entry exists precisely so it does not (ARCHITECTURE.md §2.1)')

if (failures.length) {
  console.error(`✗ ${failures.length} entry invariant(s) broken:\n${failures.map(f => `  - ${f}`).join('\n')}`)
  process.exit(1)
}
console.log('✓ entry invariants hold: optional peers confined, core free of vue, satellites sharing the root')
