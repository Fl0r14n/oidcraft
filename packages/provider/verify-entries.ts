/// <reference types="bun" />
/** Checks the invariants the build entries rely on. Every one of them fails silently: a `node:`
 * import in a shared entry makes the package node-only by accident, and a core type inlined into an
 * entry compiles fine while quietly shipping a second copy that drifts. Run after `build`. */
import { readFileSync } from 'node:fs'

const ENTRIES = {
  index: undefined,
  broker: undefined,
  interaction: undefined,
  accounts: undefined,
  'runtimes/node': 'node',
  'runtimes/bun': 'bun',
  'runtimes/deno': 'deno',
  'runtimes/workerd': 'workerd'
} as const

/** The storage libraries belong to the adapter packages. One imported here would make every host install it (ARCHITECTURE.md §2.1). */
const STORAGE_LIBRARIES = ['drizzle-orm', 'kysely', 'typeorm', 'pg'] as const

/** The browser-facing half of the client. The provider never depends on it, which is what keeps
 * `localStorage` and a token lifecycle out of the server (ARCHITECTURE.md §2.1). */
const CLIENT_ONLY = '@oidcraft/client'

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
const declares = (source: string) =>
  [...source.matchAll(/^(?:declare\s+)?(?:type|interface|const|function|class)\s+([A-Za-z0-9_$]+)/gm)].map(m => m[1] ?? '')

/**
 * The names the root actually *exports*, which is narrower than what it declares: a bundle is full of
 * private helpers. Only an exported name can be imported, so only an exported name can
 * have been inlined "instead of importing it" — matching an internal one reports a coincidence as a
 * duplication.
 */
const exports_ = (source: string) => [
  // `export { a, b as c }`, `export type { A, B }`, and the inline `export declare const d`
  ...[...source.matchAll(/^export\s+(?:type\s+)?\{([^}]*)\}/gm)]
    .flatMap(match => (match[1] ?? '').split(','))
    .map(clause => (clause.split(/\s+as\s+/).pop() ?? '').replace(/^\s*type\s+/, '').trim())
    .filter(Boolean),
  ...[...source.matchAll(/^export\s+(?:declare\s+)?(?:type|interface|const|function|class)\s+([A-Za-z0-9_$]+)/gm)].map(m => m[1] ?? '')
]

// tsdown emits exactly this for an entry that is still types-only; its runtime invariants are vacuous
// until it has code, and asserting them would fail the build for the wrong reason.
const isTypesOnly = (source: string) => source.trim() === 'export {};'

const failures: string[] = []
const check = (ok: boolean, failure: string) => {
  if (!ok) failures.push(failure)
}

const rootTypes = new Set(exports_(read('index.d.mts')))
const rootValues = new Set(exports_(read('index.mjs')))
let stubs = 0

// A parse that silently found nothing would turn both redeclaration checks below into no-ops.
check(
  rootTypes.size > 0 && rootValues.size > 0,
  'could not read the root entry\u2019s export list — the redeclaration checks would pass vacuously'
)

for (const [entry, runtime] of Object.entries(ENTRIES)) {
  const js = read(`${entry}.mjs`)
  const dts = read(`${entry}.d.mts`)

  for (const library of STORAGE_LIBRARIES) {
    check(
      !importsPackage(js, library) && !importsPackage(dts, library),
      `${entry} references ${library} — storage libraries belong to the adapter packages, never the provider`
    )
  }

  // A runtime global in a shared entry is what makes a library node-only by accident. Each runtime
  // entry owns its own; everything else must stay portable (FR-R1, FR-R3).
  if (runtime !== 'node') {
    const offending = imports(js).filter(id => id.startsWith('node:'))
    check(
      offending.length === 0,
      `${entry} imports ${offending.join(', ')} — only the /runtimes/node entry may touch node: builtins (FR-R1)`
    )
  }
  for (const [global, owner] of [
    ['Bun', 'bun'],
    ['Deno', 'deno']
  ] as const) {
    if (runtime === owner) continue
    check(
      !new RegExp(`(^|[^.\\w])${global}\\.`).test(js),
      `${entry} reaches for the ${global} global — only the /runtimes/${owner} entry may, or the package stops running anywhere else (FR-R1)`
    )
  }

  const missing = [...new Set([...undeclared(js), ...undeclared(dts)])]
  check(
    missing.length === 0,
    `${entry} imports ${missing.join(', ')}, which package.json does not declare — it resolves to nothing once installed`
  )
  check(
    !importsPackage(js, CLIENT_ONLY) && !importsPackage(dts, CLIENT_ONLY),
    `${entry} imports ${CLIENT_ONLY} — the provider never depends on the browser client`
  )

  if (entry === 'index') continue

  // A core name redeclared here is either an inlined copy or a shadow of an exported one. Both are
  // reported: the first is a real duplication, the second is a reader hazard worth renaming anyway.
  const inlined = declares(dts).filter(name => rootTypes.has(name))
  check(
    inlined.length === 0,
    `${entry}.d.mts redeclares ${inlined.join(', ')} — it has inlined core types instead of importing them from '@oidcraft/provider'`
  )

  // An entry may legitimately depend on the root for types alone — those are erased, so a missing
  // runtime import proves nothing. What must never happen is the root's *runtime* symbols being
  // copied in: that compiles, ships twice, and drifts.
  const inlinedRuntime = declares(js).filter(name => rootValues.has(name))
  check(
    inlinedRuntime.length === 0,
    `${entry}.mjs redeclares ${inlinedRuntime.join(', ')} — it has inlined core runtime code instead of importing it from '@oidcraft/provider'`
  )

  if (isTypesOnly(js)) stubs++
}

// The contract is a package of its own so an adapter release and a provider release stay independent; a compiled-in copy ties them again.
check(
  importsPackage(read('index.mjs'), '@oidcraft/adapter'),
  'index does not import @oidcraft/adapter by name — it has inlined the contract'
)

// The relying-party leg is the protocol the client bindings depend on too; a compiled-in copy drifts from it.
check(importsPackage(read('broker.mjs'), '@oidcraft/core'), 'broker does not import @oidcraft/core by name — it has inlined it')

check(
  !importsPackage(read('index.mjs'), '@oidcraft/provider'),
  'index.mjs imports @oidcraft/provider — the root is the package, it cannot depend on itself'
)

if (failures.length) {
  console.error(`✗ ${failures.length} entry invariant(s) broken:\n${failures.map(f => `  - ${f}`).join('\n')}`)
  process.exit(1)
}

const note = stubs > 0 ? ` (${stubs} entries still types-only)` : ''
console.log(
  `✓ entry invariants hold: no storage library, every import declared, no client runtime, no inlined core types, no node: outside /runtimes/node${note}`
)
