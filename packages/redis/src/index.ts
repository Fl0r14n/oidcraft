import { type FromKvOptions, type FullAdapter, fromKv, type KvEntry, type KvStore } from '@oidcraft/adapter'

/** One Redis command as the host's client sends it, e.g. ioredis `(command, args) => redis.call(command, ...args)`. */
export type RedisCommand = (command: string, args: string[]) => Promise<unknown>

export type RedisKvOptions = {
  /** Every key this adapter writes starts with it, so one Redis can hold other data, or other providers. */
  prefix?: string
  /** Keys read per round trip of a scan. */
  scanCount?: number
}

export type RedisAdapterOptions = FromKvOptions & RedisKvOptions

// `SCAN MATCH` reads every key, so names live in a sorted set read by lex range, and lapses in one scored by expiry (NFR-P1).
const NAMES = '~keys'
const LAPSES = '~expiry'

// A key the sweep finds still present was rewritten since; only its lapse entry goes.
const SWEEP = `
  local time = redis.call('TIME')
  local now = time[1] * 1000 + math.floor(time[2] / 1000)
  for _, name in ipairs(redis.call('ZRANGEBYSCORE', KEYS[3], '-inf', now - 1000, 'LIMIT', 0, 16)) do
    if redis.call('EXISTS', ARGV[1] .. name) == 0 then redis.call('ZREM', KEYS[2], name) end
    redis.call('ZREM', KEYS[3], name)
  end
`

// KEYS: the entry, the names, the lapses. ARGV: prefix, name, value, ttl in ms or '', 'NX' or ''.
const WRITE = `
  local args = { KEYS[1], ARGV[3] }
  if ARGV[5] ~= '' then args[#args + 1] = 'NX' end
  if ARGV[4] ~= '' then
    args[#args + 1] = 'PX'
    args[#args + 1] = ARGV[4]
  end
  if not redis.call('SET', unpack(args)) then return 0 end
  redis.call('ZADD', KEYS[2], 0, ARGV[2])
  if ARGV[4] == '' then
    redis.call('ZREM', KEYS[3], ARGV[2])
  else
    local time = redis.call('TIME')
    redis.call('ZADD', KEYS[3], time[1] * 1000 + math.floor(time[2] / 1000) + ARGV[4], ARGV[2])
  end
  ${SWEEP}
  return 1
`

const REMOVE = `
  redis.call('DEL', KEYS[1])
  redis.call('ZREM', KEYS[2], ARGV[2])
  redis.call('ZREM', KEYS[3], ARGV[2])
  return 1
`

// Checked and removed in one step: a name whose key came back between a scan's read and this must stay.
const FORGET = `
  for index = 2, #ARGV do
    if redis.call('EXISTS', ARGV[1] .. ARGV[index]) == 0 then redis.call('ZREM', KEYS[2], ARGV[index]) end
  end
  return 1
`

/** A `KvStore` over Redis (FR-A3); each write is one script over three keys, so on a cluster the prefix must carry a hash tag. */
export const redisKv = (send: RedisCommand, options: RedisKvOptions = {}): KvStore => {
  const prefix = options.prefix ?? 'oidcraft:'
  const count = String(options.scanCount ?? 200)
  const names = prefix + NAMES
  const lapses = prefix + LAPSES
  // An entry whose ttl has already run out is born absent, as it is in the memory store.
  const lapsed = (ttl: KvEntry['ttl']) => ttl !== undefined && ttl <= 0
  const run = (script: string, key: string, ...args: string[]) =>
    send('EVAL', [script, '3', prefix + key, names, lapses, prefix, key, ...args])
  const write = async ({ key, value, ttl }: KvEntry, mode: '' | 'NX') =>
    Number(await run(WRITE, key, value, ttl === undefined ? '' : String(Math.ceil(ttl * 1000)), mode)) === 1

  return {
    async find(key) {
      const value = await send('GET', [prefix + key])
      return typeof value === 'string' ? { key, value } : undefined
    },
    async upsert(entry) {
      if (lapsed(entry.ttl)) await run(REMOVE, entry.key)
      else await write(entry, '')
    },
    async insert(entry) {
      if (lapsed(entry.ttl)) return Number(await send('EXISTS', [prefix + entry.key])) === 0
      return write(entry, 'NX')
    },
    async destroy(key) {
      await run(REMOVE, key)
    },
    async *scan(start) {
      let from = `[${start}`
      for (;;) {
        const found = (await send('ZRANGEBYLEX', [names, from, '+', 'LIMIT', '0', count])) as string[]
        // The names are in byte order, so those under the prefix are together and the first that is not ends them.
        const under = found.filter(name => name.startsWith(start))
        if (under.length) {
          const values = (await send(
            'MGET',
            under.map(name => prefix + name)
          )) as (string | null)[]
          // Expired or deleted since it was named: absent, and the names can forget it.
          const gone = under.filter((_, index) => typeof values[index] !== 'string')
          if (gone.length) await send('EVAL', [FORGET, '3', prefix, names, lapses, prefix, ...gone])
          for (const [index, key] of under.entries()) {
            const value = values[index]
            if (typeof value === 'string') yield { key, value }
          }
        }
        if (under.length < found.length || found.length === 0) return
        from = `(${found.at(-1)}`
      }
    }
  }
}

/** A complete `Adapter` over Redis: `fromKv` over `redisKv` (FR-A3). */
export const redisAdapter = (send: RedisCommand, options: RedisAdapterOptions): FullAdapter => {
  const { prefix, scanCount, ...kv } = options
  return fromKv(redisKv(send, { ...(prefix !== undefined && { prefix }), ...(scanCount !== undefined && { scanCount }) }), kv)
}
