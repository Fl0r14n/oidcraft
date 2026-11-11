/// <reference types="bun" />
/** Checks the invariants the build entries rely on. Every one of them fails silently: axios leaking
 * into the root only shows up as a resolution error in a consumer who never installed it, and a
 * relative import across an entry boundary inlines a second copy of `oauthKey`, after which every
 * composable in that entry resolves nothing. Run after `build`. */
import { readFileSync } from 'node:fs'

const read = (name: string) => readFileSync(`dist/${name}`, 'utf8')
const imports = (source: string) => [...source.matchAll(/^(?:import|export)\s.*?from\s*["']([^"']+)["']/gm)].map(m => m[1] ?? '')
const importsPackage = (source: string, name: string) => imports(source).some(id => id === name || id.startsWith(`${name}/`))

const manifest = JSON.parse(readFileSync('package.json', 'utf8'))
const declared = new Set<string>([
  manifest.name,
  ...Object.keys(manifest.dependencies ?? {}),
  ...Object.keys(manifest.peerDependencies ?? {})
])
const packageOf = (id: string) =>
  id
    .split('/')
    .slice(0, id.startsWith('@') ? 2 : 1)
    .join('/')
/** Packages a bundle imports that its manifest does not declare: each one resolves to nothing once installed. */
const undeclared = (source: string) => [
  ...new Set(
    imports(source)
      .filter(id => !id.startsWith('.') && !id.startsWith('node:'))
      .map(packageOf)
      .filter(name => !declared.has(name))
  )
]

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
  const missing = undeclared(js)
  check(missing.length === 0, `${entry} imports ${missing.join(', ')}, which package.json does not declare`)
}

// The protocol is a dependency shared with every other binding; a copy compiled in drifts from it.
check(importsPackage(read('core.mjs'), '@oidcraft/core'), 'core does not import @oidcraft/core by name — it has inlined it')

// The satellite entries must reach the root by package name. A relative import would inline a second
// `oauthKey` symbol, and `useOAuthHttp()` would then never find what `app.use()` provided.
for (const entry of ['axios', 'component'] as const) {
  check(
    importsPackage(read(`${entry}.mjs`), '@oidcraft/vue'),
    `${entry} does not import @oidcraft/vue by package name — it has inlined the root instead of sharing its injection keys`
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
