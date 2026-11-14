/// <reference types="bun" />
import type { BunPlugin } from 'bun'

/** `@vuetify/v0` as only Vite bundles it: Bun hands a cyclic import still evaluating over as `null`, and replaces no `process.env.VITE_*` (ARCHITECTURE.md §8.1). */
const PATCHES: { file: RegExp; from: string; to: string }[] = [
  { file: /[\\/]@vuetify[\\/]v0[\\/]dist[\\/]utilities[\\/]instance\.mjs$/, from: 'isArray(holders)', to: 'Array.isArray(holders)' },
  { file: /[\\/]@vuetify[\\/]v0[\\/]dist[\\/]constants[\\/]globals\.mjs$/, from: 'process.env.VITE_LOGGER_ENABLED', to: 'undefined' }
]

export const vuetifyV0 = {
  name: 'oidcraft-vuetify-v0',
  setup(build) {
    build.onLoad({ filter: /[\\/]@vuetify[\\/]v0[\\/]dist[\\/](utilities[\\/]instance|constants[\\/]globals)\.mjs$/ }, async ({ path }) => {
      const patch = PATCHES.find(({ file }) => file.test(path))
      const source = await Bun.file(path).text()
      if (!patch || !source.includes(patch.from)) {
        throw new Error(`@vuetify/v0 changed ${path}: check whether the oidcraft-vuetify-v0 patch is still needed`)
      }
      return { contents: source.replaceAll(patch.from, patch.to), loader: 'js' }
    })
  }
} satisfies BunPlugin

export default vuetifyV0
