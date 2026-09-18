/// <reference types="bun" />
/** Checks what the two entries claim. Both failures are silent: an unpublished workspace package
 * surviving as an import resolves to nothing once installed, and Angular leaking into `./core` only
 * shows up for whoever tried to use it from a worker. Run after `build`. */
import { readFileSync } from 'node:fs'

const read = (name: string) => readFileSync(`dist/${name}`, 'utf8')
const imports = (source: string) => [...source.matchAll(/^import\s.*?from\s*["']([^"']+)["']/gm)].map(m => m[1] ?? '')
const importsPackage = (source: string, name: string) => imports(source).some(id => id === name || id.startsWith(`${name}/`))

const failures: string[] = []
const check = (ok: boolean, failure: string) => {
  if (!ok) failures.push(failure)
}

for (const entry of ['index', 'core'] as const) {
  const js = read(`${entry}.mjs`)
  for (const internal of ['@oidcraft/core', '@oidcraft/client']) {
    check(!importsPackage(js, internal), `${entry} imports ${internal}, which is never published — it must be bundled in`)
  }
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
console.log('✓ entry invariants hold: workspace packages bundled, core free of angular, no decorators emitted')
