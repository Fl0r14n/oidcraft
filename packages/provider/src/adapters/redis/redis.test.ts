/// <reference types="bun" />

import { afterAll, describe, expect, test } from 'bun:test'
import { RedisClient } from 'bun'
import { generatedKeyStore } from '../../keys/keys'
import { adapterConformance } from '../conformance'
import { redisAdapter, redisKv } from './index'

/**
 * Runs against a real Redis when REDIS_URL is set, as CI does. The memory store is atomic for free;
 * this is where `insert` being `SET NX` is actually what keeps parallel redemptions to one (FR-A3).
 */
const url = Bun.env.REDIS_URL
const client = url ? new RedisClient(url) : undefined
const send = (command: string, args: string[]) => (client as RedisClient).send(command, args)
let namespace = 0
const fresh = () => `oidcraft-test:${process.pid}:${Date.now()}:${namespace++}:`

const accounts = {
  async find(accountId: string) {
    return { accountId, claims: {} }
  },
  async claims() {
    return {}
  }
}

afterAll(async () => {
  if (!client) return
  let cursor = '0'
  do {
    const [next, keys] = (await client.send('SCAN', [cursor, 'MATCH', `oidcraft-test:${process.pid}:*`, 'COUNT', '500'])) as [
      string,
      string[]
    ]
    cursor = String(next)
    if (keys.length) await client.send('DEL', keys)
  } while (cursor !== '0')
  client.close()
})

describe.skipIf(!client)('redis adapter', () => {
  adapterConformance('redis', async () => redisAdapter(send, { prefix: fresh(), keys: await generatedKeyStore(), accounts }))

  test('insert is SET NX: of many parallel inserts exactly one wins', async () => {
    const kv = redisKv(send, { prefix: fresh() })
    const results = await Promise.all(Array.from({ length: 20 }, (_, index) => kv.insert({ key: 'once', value: String(index), ttl: 60 })))
    expect(results.filter(Boolean)).toHaveLength(1)
  })

  test('a prefix keeps two providers on one Redis apart, even with glob characters in it', async () => {
    const a = redisKv(send, { prefix: `${fresh()}a*[x]:` })
    const b = redisKv(send, { prefix: `${fresh()}b:` })
    await a.upsert({ key: 'k/1', value: 'a' })
    await b.upsert({ key: 'k/1', value: 'b' })
    const seen: string[] = []
    for await (const { key, value } of a.scan('k/')) seen.push(`${key}=${value}`)
    expect(seen).toEqual(['k/1=a'])
    expect((await b.find('k/1'))?.value).toBe('b')
  })

  test('scan walks every round of a large keyspace, once each', async () => {
    const kv = redisKv(send, { prefix: fresh(), scanCount: 7 })
    await Promise.all(Array.from({ length: 50 }, (_, index) => kv.upsert({ key: `many/${index}`, value: String(index) })))
    const seen: string[] = []
    for await (const { key } of kv.scan('many/')) seen.push(key)
    expect(seen).toHaveLength(50)
    expect(new Set(seen).size).toBe(50)
  })

  test('an entry expires by its ttl in Redis itself', async () => {
    const kv = redisKv(send, { prefix: fresh() })
    await kv.upsert({ key: 'short', value: 'v', ttl: 1 })
    expect((await kv.find('short'))?.value).toBe('v')
    await Bun.sleep(1100)
    expect(await kv.find('short')).toBeUndefined()
  })
})
