/// <reference types="bun" />
/** Checks what the build relies on and nothing else would catch: an import the manifest does not
 * declare resolves here and nowhere else, and a compiled-in copy of `@oidcraft/adapter` ships record
 * types that drift from the contract the provider reads. Run after `build`. */
import { readFileSync } from 'node:fs'

const PEERS = ['@oidcraft/adapter', 'typeorm']

const js = readFileSync('dist/index.mjs', 'utf8')
const dts = readFileSync('dist/index.d.mts', 'utf8')
const imports = (source: string) => [...source.matchAll(/^(?:import|export)\s.*?from\s*["']([^"']+)["']/gm)].map(m => m[1] ?? '')
const packageOf = (id: string) =>
  id
    .split('/')
    .slice(0, id.startsWith('@') ? 2 : 1)
    .join('/')

const manifest = JSON.parse(readFileSync('package.json', 'utf8'))
const declared = new Set<string>([...Object.keys(manifest.dependencies ?? {}), ...Object.keys(manifest.peerDependencies ?? {})])
const used = new Set([...imports(js), ...imports(dts)].filter(id => !id.startsWith('.')).map(packageOf))

const failures = [
  ...[...used].filter(name => !declared.has(name)).map(name => `imports ${name}, which package.json does not declare`),
  ...[...used]
    .filter(name => name.startsWith('node:') || name.startsWith('bun:'))
    .map(name => `imports ${name} — an adapter runs in every runtime (FR-R1)`),
  ...(/(^|[^.\w])(Bun|Deno)\./.test(js) ? ['reaches for a runtime global — an adapter runs in every runtime (FR-R1)'] : []),
  ...PEERS.filter(peer => !used.has(peer)).map(peer => `does not import ${peer} by name — it has inlined or lost it`)
]

if (failures.length) {
  console.error(`✗ ${manifest.name}:\n${failures.map(f => `  - ${f}`).join('\n')}`)
  process.exit(1)
}
console.log(`✓ ${manifest.name}: every import declared, ${PEERS.join(' and ')} imported by name, no runtime builtins`)
