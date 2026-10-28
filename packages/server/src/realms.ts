import type { RealmStore } from './adapter'
import type { AuditEvent, ProviderConfig } from './config'
import { createProvider, type Provider } from './provider'
import type { Realm, Seconds } from './types'

export type RealmsConfig = {
  /** Where realm records live, usually the control plane's `adapter.realms`. */
  store: RealmStore
  /** Which realm a request names, or undefined when it names none. The host owns the URL scheme. */
  realmOf: (request: Request) => string | undefined
  /** The provider config for a realm that exists and is enabled; `createProvider` validates it as ever. */
  configure: (realm: Realm) => ProviderConfig | Promise<ProviderConfig>
  /** Creates the realm's storage and its own keys — never `generatedKeyStore()`, whose RSA key is per process. Runs before the realm can be served; a throw undoes the create. */
  provision?: (realm: Realm) => void | Promise<void>
  /** Drops the realm's storage. Runs after the realm stopped being served, before its record goes. */
  retire?: (realm: Realm) => void | Promise<void>
  /** How long a process trusts its cached provider before re-reading the record; any change rebuilds it. Default 30. */
  revalidate?: Seconds
  onAudit?: (event: AuditEvent) => void | Promise<void>
}

export type RealmInput = { id: string; displayName?: string; settings?: Record<string, unknown> }

export type RealmPatch = { displayName?: string; settings?: Record<string, unknown> }

// A realm id becomes part of an issuer's host or path, so anything else could forge one (NFR-S6).
const REALM_ID = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/

export const isRealmId = (id: string) => REALM_ID.test(id)

type Built = { provider: Provider; record: string }

// The whole record, not updatedAt: two writes in one millisecond, or an edit made straight in the
// database, change what configure would build without necessarily changing the timestamp.
const fingerprint = (realm: Realm) => JSON.stringify(realm)
type Entry = { built: Promise<Built | undefined>; checkedAt: number }

/**
 * Several issuers in one process, each an ordinary `Provider` built on first use (FR-M4). A single
 * issuer never needs this: `createProvider` alone is the whole deployment.
 */
export const createRealms = (options: RealmsConfig) => {
  const { store } = options
  const revalidate = (options.revalidate ?? 30) * 1000
  const cache = new Map<string, Entry>()
  const signers = new Map<string, string>()

  /**
   * A key two realms share lets a token one of them signed verify against the other's JWKS. The
   * likeliest cause is `generatedKeyStore()`, which keeps one RSA key per process (FR-M4).
   */
  const claimKeys = async (id: string, provider: Provider) => {
    const kids = (await provider.config.adapter.keys.active()).map(key => key.kid)
    for (const kid of kids) {
      const owner = signers.get(kid)
      if (owner !== undefined && owner !== id)
        throw new Error(`realms ${owner} and ${id} share signing key ${kid}; each realm needs its own keys`)
    }
    for (const [kid, owner] of signers) if (owner === id) signers.delete(kid)
    for (const kid of kids) signers.set(kid, id)
  }

  const load = async (id: string, previous: Promise<Built | undefined> | undefined): Promise<Built | undefined> => {
    const realm = await store.find(id)
    if (!realm?.enabled) return undefined
    const before = await previous?.catch(() => undefined)
    if (before && before.record === fingerprint(realm)) return before
    const provider = createProvider(await options.configure(realm))
    await claimKeys(id, provider)
    return { provider, record: fingerprint(realm) }
  }

  const get = async (id: string) => {
    if (!isRealmId(id)) return undefined
    const cached = cache.get(id)
    if (cached && Date.now() - cached.checkedAt < revalidate) return (await cached.built)?.provider
    // Concurrent requests for a cold realm share this build. An unknown or failed realm is not
    // remembered: random names cannot fill the cache, and an outage cannot pin a realm as broken.
    const entry: Entry = { built: load(id, cached?.built), checkedAt: Date.now() }
    cache.set(id, entry)
    const settle = () => {
      if (cache.get(id) === entry) cache.delete(id)
    }
    entry.built.then(built => built ?? settle(), settle)
    return (await entry.built)?.provider
  }

  const forget = (id: string) => {
    cache.delete(id)
    for (const [kid, owner] of signers) if (owner === id) signers.delete(kid)
  }

  const audit = async (action: string, id: string) => {
    await options.onAudit?.({ action, at: new Date(), detail: { realm: id } })
  }

  const existing = async (id: string) => {
    const realm = await store.find(id)
    if (!realm) throw new Error(`realm ${id} does not exist`)
    return realm
  }

  const save = async (realm: Realm, action: string) => {
    await store.upsert(realm)
    forget(realm.id)
    await audit(action, realm.id)
    return realm
  }

  /** Functions, not routes: the host decides who may call them (FR-M1). */
  const management = {
    list: () => store.list(),
    find: (id: string) => store.find(id),

    async create(input: RealmInput) {
      if (!isRealmId(input.id)) throw new Error(`realm id ${JSON.stringify(input.id)} must be a DNS label: a-z, 0-9 and inner hyphens`)
      const now = new Date()
      const realm: Realm = {
        id: input.id,
        ...(input.displayName && { displayName: input.displayName }),
        enabled: false,
        settings: input.settings ?? {},
        createdAt: now,
        updatedAt: now
      }
      if (!(await store.create(realm))) throw new Error(`realm ${input.id} already exists`)
      try {
        await options.provision?.(realm)
      } catch (error) {
        await store.destroy(realm.id)
        throw error
      }
      return save({ ...realm, enabled: true, updatedAt: new Date() }, 'realm.create')
    },

    async update(id: string, patch: RealmPatch) {
      const realm = await existing(id)
      return save({ ...realm, ...patch, updatedAt: new Date() }, 'realm.update')
    },

    async enable(id: string) {
      return save({ ...(await existing(id)), enabled: true, updatedAt: new Date() }, 'realm.enable')
    },

    async disable(id: string) {
      return save({ ...(await existing(id)), enabled: false, updatedAt: new Date() }, 'realm.disable')
    },

    /** Disabled first, so a failed `retire` leaves a realm nobody is served and the removal can be retried. */
    async remove(id: string) {
      const realm = await existing(id)
      await store.upsert({ ...realm, enabled: false, updatedAt: new Date() })
      forget(id)
      await options.retire?.(realm)
      await store.destroy(id)
      await audit('realm.remove', id)
    }
  }

  return {
    /** The realm's provider, or undefined when the request names no enabled realm. */
    resolve: (request: Request) => {
      const id = options.realmOf(request)
      return id === undefined ? Promise.resolve(undefined) : get(id)
    },
    get,
    forget,
    management
  }
}

export type Realms = ReturnType<typeof createRealms>
