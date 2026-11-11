import { describe, expect, test } from 'bun:test'
import { adapterConformance } from '../conformance'
import { memoryAdapter, memoryKv } from './index'

describe('memory adapter', () => {
  adapterConformance('memory', () => memoryAdapter())

  test('an entry expires by its ttl without a sweep', async () => {
    const kv = memoryKv()
    await kv.upsert({ key: 'k', value: 'v', ttl: 1 })
    expect((await kv.find('k'))?.value).toBe('v')
    await kv.upsert({ key: 'k', value: 'v', ttl: -1 })
    expect(await kv.find('k')).toBeUndefined()
  })

  test('scan yields only the prefix it was asked for', async () => {
    const kv = memoryKv()
    await kv.upsert({ key: 'a/1', value: '1' })
    await kv.upsert({ key: 'a/2', value: '2' })
    await kv.upsert({ key: 'b/1', value: '3' })
    const seen: string[] = []
    for await (const { key } of kv.scan('a/')) seen.push(key)
    expect(seen.sort()).toEqual(['a/1', 'a/2'])
  })

  test('insert writes only what is absent or lapsed', async () => {
    const kv = memoryKv()
    expect(await kv.insert({ key: 'k', value: '1' })).toBe(true)
    expect(await kv.insert({ key: 'k', value: '2' })).toBe(false)
    expect((await kv.find('k'))?.value).toBe('1')
    await kv.upsert({ key: 'k', value: '3', ttl: -1 })
    expect(await kv.insert({ key: 'k', value: '4' })).toBe(true)
  })
})
