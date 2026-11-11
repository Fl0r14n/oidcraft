// Imports every published entry of the server-side packages under whatever `node` runs this. CI runs
// it on the oldest Node `engines` claims (FR-R3): a builtin export that only exists in a newer Node
// fails the whole entry at load, and no test on the newest Node can see that.
import { readFileSync } from 'node:fs'

let failed = 0
for (const dir of ['core', 'client', 'adapter', 'provider', 'drizzle', 'kysely', 'typeorm', 'redis']) {
  const { name, exports } = JSON.parse(readFileSync(new URL(`../packages/${dir}/package.json`, import.meta.url), 'utf8'))
  for (const subpath of Object.keys(exports).filter(key => key !== './package.json')) {
    const id = `${name}${subpath.slice(1)}`
    try {
      await import(id)
      console.log(`✓ ${id}`)
    } catch (error) {
      failed++
      console.error(`✗ ${id}: ${error instanceof Error ? error.message : String(error)}`)
    }
  }
}
console.log(`${failed ? '✗' : '✓'} every entry ${failed ? `but ${failed} ` : ''}loads on Node ${process.version}`)
process.exit(failed ? 1 : 0)
