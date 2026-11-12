/// <reference types="bun" />

import { afterAll, describe, expect, test } from 'bun:test'
import { generatedKeyStore } from '@oidcraft/adapter'
import { adapterConformance } from '@oidcraft/adapter/conformance'
import { RedisClient } from 'bun'
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
  for (const check of adapterConformance(async () => redisAdapter(send, { prefix: fresh(), keys: await generatedKeyStore(), accounts }), {
    implements: ['identities', 'credentials', 'realms']
  })) {
    test(`redis: ${check.name}`, check.run)
  }

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

  // NFR-P1: Redis SCAN walks every key whatever the pattern, so a prefix scan must not be one.
  test('a prefix scan costs what it matches, not what the store holds', async () => {
    const prefix = fresh()
    const commands: string[] = []
    const counting = (command: string, args: string[]) => {
      commands.push(command)
      return send(command, args)
    }
    const kv = redisKv(counting, { prefix })
    await Promise.all(Array.from({ length: 300 }, (_, index) => kv.upsert({ key: `artifact/access_token/${index}`, value: 'x', ttl: 60 })))
    await kv.upsert({ key: 'session-client/s1/a', value: '' })
    await kv.upsert({ key: 'session-client/s1/b', value: '' })
    await kv.upsert({ key: 'session-client/s10/c', value: '' })

    commands.length = 0
    const seen: string[] = []
    for await (const { key } of kv.scan('session-client/s1/')) seen.push(key)
    expect(seen.sort()).toEqual(['session-client/s1/a', 'session-client/s1/b'])
    expect(commands).not.toContain('SCAN')
    expect(commands.length).toBeLessThanOrEqual(3)
  })

  test('a scan leaves out what expired or was destroyed, and a key written again comes back', async () => {
    const kv = redisKv(send, { prefix: fresh() })
    await kv.upsert({ key: 'g/short', value: '1', ttl: 1 })
    await kv.upsert({ key: 'g/gone', value: '2' })
    await kv.upsert({ key: 'g/kept', value: '3' })
    await kv.destroy('g/gone')
    await Bun.sleep(1100)
    const keys = async () => {
      const seen: string[] = []
      for await (const { key } of kv.scan('g/')) seen.push(key)
      return seen.sort()
    }
    expect(await keys()).toEqual(['g/kept'])
    await kv.upsert({ key: 'g/short', value: 'again' })
    expect(await keys()).toEqual(['g/kept', 'g/short'])
  })

  // The index must not grow with every token ever issued: writes sweep what has expired.
  test('the index forgets expired keys nobody scans for', async () => {
    const prefix = fresh()
    const kv = redisKv(send, { prefix })
    await Promise.all(Array.from({ length: 40 }, (_, index) => kv.upsert({ key: `t/${index}`, value: 'x', ttl: 1 })))
    await Bun.sleep(2200)
    for (let index = 0; index < 10; index++) await kv.upsert({ key: `live/${index}`, value: 'x' })
    expect(Number(await send('ZCARD', [`${prefix}~keys`]))).toBe(10)
  })

  test('an entry expires by its ttl in Redis itself', async () => {
    const kv = redisKv(send, { prefix: fresh() })
    await kv.upsert({ key: 'short', value: 'v', ttl: 1 })
    expect((await kv.find('short'))?.value).toBe('v')
    await Bun.sleep(1100)
    expect(await kv.find('short')).toBeUndefined()
  })
})
