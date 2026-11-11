/// <reference types="bun" />
/** Checks the invariants the build entries rely on. Each fails silently: a record type compiled into
 * `./memory` ships a second copy that drifts from the contract, and an import the manifest does not
 * declare resolves here and nowhere else. Run after `build`. */
import { readFileSync } from 'node:fs'

const ENTRIES = ['index', 'memory', 'conformance'] as const

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
const undeclared = (source: string) => [
  ...new Set(
    imports(source)
      .filter(id => !id.startsWith('.'))
      .map(packageOf)
      .filter(name => !declared.has(name))
  )
]
const declares = (source: string) =>
  [...source.matchAll(/^(?:declare\s+)?(?:type|interface|const|function|class)\s+([A-Za-z0-9_$]+)/gm)].map(m => m[1] ?? '')
const exported = (source: string) => [
  ...[...source.matchAll(/^export\s+(?:type\s+)?\{([^}]*)\}/gm)]
    .flatMap(match => (match[1] ?? '').split(','))
    .map(clause => (clause.split(/\s+as\s+/).pop() ?? '').replace(/^\s*type\s+/, '').trim())
    .filter(Boolean),
  ...[...source.matchAll(/^export\s+(?:declare\s+)?(?:type|interface|const|function|class)\s+([A-Za-z0-9_$]+)/gm)].map(m => m[1] ?? '')
]

const failures: string[] = []
const check = (ok: boolean, failure: string) => {
  if (!ok) failures.push(failure)
}

const rootNames = new Set([...exported(read('index.d.mts')), ...exported(read('index.mjs'))])
check(rootNames.size > 0, 'could not read the root entry’s export list — the redeclaration check would pass vacuously')

for (const entry of ENTRIES) {
  const js = read(`${entry}.mjs`)
  const dts = read(`${entry}.d.mts`)

  // The provider and every adapter run wherever the host does (FR-R1).
  const builtins = imports(js).filter(id => id.startsWith('node:') || id.startsWith('bun:'))
  check(builtins.length === 0, `${entry} imports ${builtins.join(', ')} — the contract runs in every runtime (FR-R1)`)
  check(!/(^|[^.\w])(Bun|Deno)\./.test(js), `${entry} reaches for a runtime global — the contract runs in every runtime (FR-R1)`)

  const missing = [...new Set([...undeclared(js), ...undeclared(dts)])]
  check(missing.length === 0, `${entry} imports ${missing.join(', ')}, which package.json does not declare`)

  if (entry === 'index') continue
  const inlined = [...new Set([...declares(dts), ...declares(js)])].filter(name => rootNames.has(name))
  check(
    inlined.length === 0,
    `${entry} redeclares ${inlined.join(', ')} — it has inlined the root instead of importing '@oidcraft/adapter'`
  )
  check(
    importsPackage(js, '@oidcraft/adapter') || importsPackage(dts, '@oidcraft/adapter'),
    `${entry} does not import '@oidcraft/adapter' by name`
  )
}

// The suite exists for adapters tested under any runner; importing one would tie it to that runner.
const runners = imports(read('conformance.mjs')).filter(id => /^(bun:|node:test|vitest|@jest\/|jest$)/.test(id))
check(runners.length === 0, `conformance imports ${runners.join(', ')} — it must run under any test runner (FR-A6)`)

if (failures.length) {
  console.error(`✗ ${failures.length} entry invariant(s) broken:\n${failures.map(f => `  - ${f}`).join('\n')}`)
  process.exit(1)
}
console.log('✓ entry invariants hold: every import declared, the root imported by name, no runtime builtins, a runner-free suite')
