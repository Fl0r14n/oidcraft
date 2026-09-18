/// <reference types="bun" />
import { describe, expect, test } from 'bun:test'
import { readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'
import manifest from './package.json'

/** Adding an entry means touching three places. Forgetting one of them fails silently: the build
 * still succeeds, and the entry is simply unreachable — or reachable and unbuilt. */

const subpaths = Object.keys(manifest.exports).filter(key => key !== './package.json')

const sourceOf = (subpath: string) => (subpath === '.' ? 'src/index.ts' : `src/${subpath.slice(2)}/index.ts`)

const exists = (path: string) => {
  try {
    return statSync(join(import.meta.dir, path)).isFile()
  } catch {
    return false
  }
}

const sourceEntries = () => {
  const found: string[] = []
  const walk = (dir: string, prefix: string) => {
    for (const name of readdirSync(join(import.meta.dir, dir), { withFileTypes: true })) {
      if (!name.isDirectory()) continue
      const child = `${dir}/${name.name}`
      if (exists(`${child}/index.ts`)) found.push(`./${prefix}${name.name}`)
      walk(child, `${prefix}${name.name}/`)
    }
  }
  walk('src', '')
  return found
}

describe('exports map', () => {
  test.each(subpaths)('%s has a source file', subpath => {
    expect({ subpath, source: sourceOf(subpath), exists: exists(sourceOf(subpath)) }).toEqual({
      subpath,
      source: sourceOf(subpath),
      exists: true
    })
  })

  test('every source entry is exported', () => {
    expect(sourceEntries().filter(entry => !subpaths.includes(entry))).toEqual([])
  })

  test.each(subpaths)('%s declares types and import that agree', subpath => {
    const entry = manifest.exports[subpath as keyof typeof manifest.exports] as { types: string; import: string }
    expect(entry.types).toBe(entry.import.replace(/\.mjs$/, '.d.mts'))
  })

  test('every subpath points inside dist', () => {
    for (const subpath of subpaths) {
      const entry = manifest.exports[subpath as keyof typeof manifest.exports] as { import: string }
      expect(entry.import.startsWith('./dist/')).toBe(true)
    }
  })
})
