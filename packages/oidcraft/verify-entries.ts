/// <reference types="bun" />
/** Checks the invariants the build entries rely on. Every one of them fails silently: an optional
 * peer leaking into the root only surfaces as a resolution error in a consumer who never installed
 * it, and a core type inlined into an entry compiles fine while quietly shipping a second copy that
 * drifts. Run after `build`. */
import { readFileSync } from 'node:fs'

const ENTRIES = {
  index: { owns: [] as string[], mayUseNode: false },
  federation: { owns: ['openid-client'], mayUseNode: false },
  interaction: { owns: [], mayUseNode: false },
  node: { owns: [], mayUseNode: true },
  'adapters/memory': { owns: [], mayUseNode: false },
  'adapters/drizzle': { owns: ['drizzle-orm'], mayUseNode: false },
  'adapters/kysely': { owns: ['kysely'], mayUseNode: false }
} as const

const OPTIONAL_PEERS = ['openid-client', 'drizzle-orm', 'kysely'] as const

const read = (name: string) => readFileSync(`dist/${name}`, 'utf8')
const imports = (source: string) => [...source.matchAll(/^import\s.*?from\s*["']([^"']+)["']/gm)].map(m => m[1] ?? '')
const importsPackage = (source: string, name: string) => imports(source).some(id => id === name || id.startsWith(`${name}/`))
const declares = (source: string) =>
  [...source.matchAll(/^(?:declare\s+)?(?:type|interface|const|function|class)\s+([A-Za-z0-9_$]+)/gm)].map(m => m[1] ?? '')

// tsdown emits exactly this for an entry that is still types-only; its runtime invariants are vacuous
// until it has code, and asserting them would fail the build for the wrong reason.
const isTypesOnly = (source: string) => source.trim() === 'export {};'

const failures: string[] = []
const check = (ok: boolean, failure: string) => {
  if (!ok) failures.push(failure)
}

const rootTypes = new Set(declares(read('index.d.mts')))
let stubs = 0

for (const [entry, { owns, mayUseNode }] of Object.entries(ENTRIES)) {
  const js = read(`${entry}.mjs`)
  const dts = read(`${entry}.d.mts`)

  // An optional peer stays optional only while nothing but the entry that owns it pulls it in.
  for (const peer of OPTIONAL_PEERS) {
    if ((owns as readonly string[]).includes(peer)) continue
    check(
      !importsPackage(js, peer) && !importsPackage(dts, peer),
      `${entry} references ${peer} — only the entry that owns it may, or the optional peer becomes required for every consumer`
    )
  }

  // The core runs on workerd and Deno only while nothing in its graph reaches for a node builtin (FR-R1).
  if (!mayUseNode) {
    const offending = imports(js).filter(id => id.startsWith('node:'))
    check(offending.length === 0, `${entry} imports ${offending.join(', ')} — only the /node entry may touch node: builtins (FR-R1)`)
  }

  if (entry === 'index') continue

  // A core type redeclared here is an inlined copy: it compiles, and it drifts from the root silently.
  const inlined = declares(dts).filter(name => rootTypes.has(name))
  check(
    inlined.length === 0,
    `${entry}.d.mts redeclares ${inlined.join(', ')} — it has inlined core types instead of importing them from 'oidcraft'`
  )

  if (isTypesOnly(js)) {
    stubs++
    continue
  }

  check(
    imports(js).includes('oidcraft'),
    `${entry}.mjs does not import the root by package name — it has inlined a second copy of the core`
  )
  for (const peer of owns) {
    check(importsPackage(js, peer), `${entry}.mjs does not import ${peer} — the entry that owns it has inlined or lost it`)
  }
}

check(!importsPackage(read('index.mjs'), 'oidcraft'), 'index.mjs imports oidcraft — the root is the package, it cannot depend on itself')

if (failures.length) {
  console.error(`✗ ${failures.length} entry invariant(s) broken:\n${failures.map(f => `  - ${f}`).join('\n')}`)
  process.exit(1)
}

const note = stubs > 0 ? ` (${stubs} entries still types-only — their runtime checks are pending)` : ''
console.log(`✓ entry invariants hold: optional peers confined, no inlined core types, no node: outside /node${note}`)
