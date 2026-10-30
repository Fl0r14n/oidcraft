import { type FromKvOptions, type FullAdapter, fromKv, type KvEntry, type KvStore } from 'oidcraft'

/**
 * One Redis command, as the host's client sends it. Taking a function rather than a client keeps
 * this entry free of any one runtime or library:
 *
 * - Bun: `(command, args) => client.send(command, args)` with `new RedisClient(url)`
 * - ioredis: `(command, args) => redis.call(command, ...args)`
 * - node-redis: `(command, args) => client.sendCommand([command, ...args])`
 */
export type RedisCommand = (command: string, args: string[]) => Promise<unknown>

export type RedisKvOptions = {
  /** Every key this adapter writes starts with it, so one Redis can hold other data, or other providers. */
  prefix?: string
  /** Keys asked for per SCAN round trip. */
  scanCount?: number
}

export type RedisAdapterOptions = FromKvOptions & RedisKvOptions

// SCAN MATCH is a glob; a prefix is literal, so its glob characters are escaped.
const globEscape = (value: string) => value.replace(/[\\*?[\]]/g, char => `\\${char}`)

/**
 * A `KvStore` over Redis (FR-A3). `insert` is `SET NX`, which Redis applies atomically, so single
 * use holds across every process sharing the instance — the property the memory store gets for free
 * and a distributed one has to earn. Expiry is Redis's own `PX`, so nothing needs sweeping.
 */
export const redisKv = (send: RedisCommand, options: RedisKvOptions = {}): KvStore => {
  const prefix = options.prefix ?? 'oidcraft:'
  const count = String(options.scanCount ?? 200)
  const expiry = (ttl: KvEntry['ttl']) => (ttl === undefined ? [] : ['PX', String(Math.ceil(ttl * 1000))])
  // An entry whose ttl has already run out is born absent, as it is in the memory store.
  const lapsed = (ttl: KvEntry['ttl']) => ttl !== undefined && ttl <= 0

  return {
    async find(key) {
      const value = await send('GET', [prefix + key])
      return typeof value === 'string' ? { key, value } : undefined
    },
    async upsert({ key, value, ttl }) {
      if (lapsed(ttl)) await send('DEL', [prefix + key])
      else await send('SET', [prefix + key, value, ...expiry(ttl)])
    },
    async insert({ key, value, ttl }) {
      if (lapsed(ttl)) return Number(await send('EXISTS', [prefix + key])) === 0
      return (await send('SET', [prefix + key, value, 'NX', ...expiry(ttl)])) === 'OK'
    },
    async destroy(key) {
      await send('DEL', [prefix + key])
    },
    async *scan(start) {
      const match = `${globEscape(prefix + start)}*`
      // SCAN may return a key more than once across its rounds.
      const seen = new Set<string>()
      let cursor = '0'
      do {
        const [next, found] = (await send('SCAN', [cursor, 'MATCH', match, 'COUNT', count])) as [string, string[]]
        cursor = String(next)
        const keys = found.filter(key => !seen.has(key))
        for (const key of keys) seen.add(key)
        if (!keys.length) continue
        const values = (await send('MGET', keys)) as (string | null)[]
        for (const [index, full] of keys.entries()) {
          const value = values[index]
          // Expired or deleted between SCAN and MGET: absent, as if the scan had never seen it.
          if (typeof value === 'string') yield { key: full.slice(prefix.length), value }
        }
      } while (cursor !== '0')
    }
  }
}

/** A complete `Adapter` over Redis: `fromKv` over `redisKv` (FR-A3). */
export const redisAdapter = (send: RedisCommand, options: RedisAdapterOptions): FullAdapter => {
  const { prefix, scanCount, ...kv } = options
  return fromKv(redisKv(send, { ...(prefix !== undefined && { prefix }), ...(scanCount !== undefined && { scanCount }) }), kv)
}
