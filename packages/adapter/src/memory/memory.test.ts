import { describe, expect, test } from 'bun:test'
import { adapterConformance } from '../conformance'
import { generatedKeyStore } from '../keys'
import { fromKv } from '../kv'
import { memoryAdapter, memoryKv } from './index'

describe('memory adapter', () => {
  for (const check of adapterConformance(() => memoryAdapter(), { implements: ['identities', 'credentials', 'passkeys', 'realms'] }))
    test(check.name, check.run)

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

  // NFR-S4: a token revoked between consume's read and its create must not come back as redeemed.
  test('consume refuses an artifact deleted while it was being consumed', async () => {
    const kv = memoryKv()
    const adapter = fromKv(
      {
        ...kv,
        async create(entry) {
          await kv.destroy('artifact/refresh_token/r1')
          return kv.create(entry)
        }
      },
      { keys: await generatedKeyStore() }
    )
    const expiresAt = new Date(Date.now() + 60_000)
    await adapter.artifacts.upsert({ id: 'r1', kind: 'refresh_token', clientId: 'rp', payload: {}, expiresAt })
    expect(await adapter.artifacts.consume('refresh_token', 'r1')).toBe(false)
  })

  // FR-I4: a merge whose lock lapsed while it worked must not release the next merge's.
  test('a merge releases only the lock it holds', async () => {
    const kv = memoryKv()
    const lock = 'grant-lock/u1/c1'
    const adapter = fromKv(
      {
        ...kv,
        async upsert(entry) {
          if (entry.key.startsWith('grant/')) await kv.upsert({ key: lock, value: 'the next merge', ttl: 5 })
          return kv.upsert(entry)
        }
      },
      { keys: await generatedKeyStore() }
    )
    const grant = { id: 'g1', accountId: 'u1', clientId: 'c1', scopes: ['openid'], claims: [], resources: {}, createdAt: new Date() }
    await adapter.grants.merge(grant)
    expect((await kv.find(lock))?.value).toBe('the next merge')
  })

  test('destroyIf removes only the value it names, and never a lapsed one', async () => {
    const kv = memoryKv()
    await kv.upsert({ key: 'k', value: 'next' })
    expect(await kv.destroyIf('k', 'lapsed')).toBe(false)
    expect(await kv.destroyIf('k', 'next')).toBe(true)
    expect(await kv.find('k')).toBeUndefined()
    await kv.upsert({ key: 'k', value: 'gone', ttl: -1 })
    expect(await kv.destroyIf('k', 'gone')).toBe(false)
  })

  test('create writes only what is absent or lapsed', async () => {
    const kv = memoryKv()
    expect(await kv.create({ key: 'k', value: '1' })).toBe(true)
    expect(await kv.create({ key: 'k', value: '2' })).toBe(false)
    expect((await kv.find('k'))?.value).toBe('1')
    await kv.upsert({ key: 'k', value: '3', ttl: -1 })
    expect(await kv.create({ key: 'k', value: '4' })).toBe(true)
  })
})
