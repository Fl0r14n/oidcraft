/// <reference types="bun" />
/** Checks what the two entries claim. Both failures are silent: an import package.json does not
 * declare resolves to nothing once installed, and Angular leaking into `./core` only
 * shows up for whoever tried to use it from a worker. Run after `build`. */
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

for (const entry of ['index', 'core'] as const) {
  const js = read(`${entry}.mjs`)
  const missing = undeclared(js)
  check(missing.length === 0, `${entry} imports ${missing.join(', ')}, which package.json does not declare`)
}

// Both are dependencies shared with every other binding; a copy compiled in drifts from them.
for (const shared of ['@oidcraft/core', '@oidcraft/client']) {
  check(importsPackage(read('core.mjs'), shared), `core does not import ${shared} by name — it has inlined it`)
}

// The claim that earns `./core` its own entry.
check(!importsPackage(read('core.mjs'), '@angular/core'), 'core imports @angular/core — the entry exists precisely so it does not')

// And the claim that lets this package skip ng-packagr: no decorator ever reaches the output.
for (const entry of ['index', 'core'] as const) {
  check(
    !/(^|\s)@[A-Z]\w*\s*\(/.test(read(`${entry}.mjs`)),
    `${entry} emits a decorator — this package builds with tsdown only while it has none (PLAN.md)`
  )
}

if (failures.length) {
  console.error(`✗ ${failures.length} entry invariant(s) broken:\n${failures.map(f => `  - ${f}`).join('\n')}`)
  process.exit(1)
}
console.log('✓ entry invariants hold: every import declared, core free of angular, no decorators emitted')
