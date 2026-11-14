/// <reference types="bun" />
import { expect, test } from 'bun:test'

const LEVELS = ['atoms', 'molecules', 'organisms', 'templates', 'pages']

/** ARCHITECTURE.md §8.1: a component imports only from the levels below its own, or its own level's siblings. */
test('every component imports only from its own level or below', async () => {
  const found: string[] = []
  for (const [rank, level] of LEVELS.entries()) {
    for await (const file of new Bun.Glob('*.vue').scan(`${import.meta.dir}/${level}`)) {
      found.push(file)
      const source = await Bun.file(`${import.meta.dir}/${level}/${file}`).text()
      for (const [, target] of source.matchAll(/from '\.\.\/(\w+)\//g)) {
        expect({ file: `${level}/${file}`, imports: target, allowed: LEVELS.indexOf(target as string) <= rank }).toMatchObject({
          allowed: true
        })
      }
    }
  }
  expect(found.length).toBeGreaterThan(20)
})

test('no component sits outside a level', async () => {
  const stray = await Array.fromAsync(new Bun.Glob('*.vue').scan(import.meta.dir))
  expect(stray).toEqual([])
})
