/// <reference types="bun" />
/** Checks the invariants the build entries rely on. Every one of them fails silently: an optional
 * peer leaking into the root only surfaces as a resolution error in a consumer who never installed
 * it, and a core type inlined into an entry compiles fine while quietly shipping a second copy that
 * drifts. Run after `build`. */
import { readFileSync } from 'node:fs'

const ENTRIES = {
  index: { owns: [] as string[], runtime: undefined },
  federation: { owns: ['openid-client'], runtime: undefined },
  interaction: { owns: [], runtime: undefined },
  'runtimes/node': { owns: [], runtime: 'node' },
  'runtimes/bun': { owns: [], runtime: 'bun' },
  'runtimes/deno': { owns: [], runtime: 'deno' },
  'runtimes/workerd': { owns: [], runtime: 'workerd' },
  'adapters/memory': { owns: [], runtime: undefined },
  'adapters/drizzle': { owns: ['drizzle-orm'], runtime: undefined },
  'adapters/kysely': { owns: ['kysely'], runtime: undefined }
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
const rootValues = new Set(declares(read('index.mjs')))
let stubs = 0

for (const [entry, { owns, runtime }] of Object.entries(ENTRIES)) {
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

  if (entry === 'index') continue

  // A core name redeclared here is either an inlined copy or a shadow of an exported one. Both are
  // reported: the first is a real duplication, the second is a reader hazard worth renaming anyway.
  const inlined = declares(dts).filter(name => rootTypes.has(name))
  check(
    inlined.length === 0,
    `${entry}.d.mts redeclares ${inlined.join(', ')} — it has inlined core types instead of importing them from 'oidcraft'`
  )

  // An entry may legitimately depend on the root for types alone — those are erased, so a missing
  // runtime import proves nothing. What must never happen is the root's *runtime* symbols being
  // copied in: that compiles, ships twice, and drifts.
  const inlinedRuntime = declares(js).filter(name => rootValues.has(name))
  check(
    inlinedRuntime.length === 0,
    `${entry}.mjs redeclares ${inlinedRuntime.join(', ')} — it has inlined core runtime code instead of importing it from 'oidcraft'`
  )

  if (isTypesOnly(js)) {
    stubs++
    continue
  }

  for (const peer of owns) {
    check(importsPackage(js, peer), `${entry}.mjs does not import ${peer} — the entry that owns it has inlined or lost it`)
  }
}

check(!importsPackage(read('index.mjs'), 'oidcraft'), 'index.mjs imports oidcraft — the root is the package, it cannot depend on itself')

if (failures.length) {
  console.error(`✗ ${failures.length} entry invariant(s) broken:\n${failures.map(f => `  - ${f}`).join('\n')}`)
  process.exit(1)
}

const note = stubs > 0 ? ` (${stubs} entries still types-only — their peer checks are pending)` : ''
console.log(`✓ entry invariants hold: optional peers confined, no inlined core types, no node: outside /runtimes/node${note}`)
