import { describe, expect, test } from 'bun:test'
import { adapterConformance } from '../../adapter-conformance'
import { memoryAdapter, memoryKv } from './index'

describe('memory adapter', () => {
  adapterConformance('memory', () => memoryAdapter())

  test('an entry expires by its ttl without a sweep', async () => {
    const kv = memoryKv()
    await kv.set('k', 'v', 1)
    expect(await kv.get('k')).toBe('v')
    await kv.set('k', 'v', -1 as never)
    expect(await kv.get('k')).toBeUndefined()
  })

  test('scan yields only the prefix it was asked for', async () => {
    const kv = memoryKv()
    await kv.set('a/1', '1')
    await kv.set('a/2', '2')
    await kv.set('b/1', '3')
    const seen: string[] = []
    for await (const { key } of kv.scan('a/')) seen.push(key)
    expect(seen.sort()).toEqual(['a/1', 'a/2'])
  })
})
