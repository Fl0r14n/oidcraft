import {
  type AccountStore,
  type Adapter,
  type FromKvOptions,
  fromKv,
  generatedKeyStore,
  type KeyStore,
  type KvEntry,
  type KvStore
} from 'oidcraft'

export type MemoryAdapterOptions = {
  keys?: KeyStore
  accounts?: AccountStore
  federation?: boolean
}

/** Everything lives in one process and dies with it. Development and tests only (FR-A4). */
export const memoryKv = (): KvStore & { size: () => number } => {
  const store = new Map<string, { value: string; expiresAt?: number }>()

  const live = (key: string) => {
    const entry = store.get(key)
    if (!entry) return undefined
    if (entry.expiresAt !== undefined && entry.expiresAt <= Date.now()) {
      store.delete(key)
      return undefined
    }
    return entry
  }

  const write = ({ key, value, ttl }: KvEntry) =>
    store.set(key, { value, ...(ttl !== undefined && { expiresAt: Date.now() + ttl * 1000 }) })

  return {
    async find(key) {
      const entry = live(key)
      return entry ? { key, value: entry.value } : undefined
    },
    async upsert(entry) {
      write(entry)
    },
    async insert(entry) {
      if (live(entry.key)) return false
      write(entry)
      return true
    },
    async destroy(key) {
      store.delete(key)
    },
    async *scan(prefix) {
      for (const key of [...store.keys()]) {
        if (!key.startsWith(prefix)) continue
        const entry = live(key)
        if (entry) yield { key, value: entry.value }
      }
    },
    size: () => store.size
  }
}

const rejectingAccounts: AccountStore = {
  async find() {
    return undefined
  },
  async claims() {
    return undefined
  }
}

export const memoryAdapter = async (options: MemoryAdapterOptions = {}): Promise<Adapter> => {
  const from: FromKvOptions = {
    keys: options.keys ?? (await generatedKeyStore()),
    accounts: options.accounts ?? rejectingAccounts,
    ...(options.federation !== undefined && { federation: options.federation })
  }
  return fromKv(memoryKv(), from)
}
