import { describe, expect, test } from 'bun:test'
import type { Adapter } from './adapter'
import { memoryAdapter } from './adapters/memory'
import type { AuditEvent, ProviderConfig } from './config'
import { generatedKeyStore, generateKey, staticKeyStore } from './keys/keys'
import { createRealms, isRealmId, type RealmsConfig } from './realms'
import type { Client, Realm } from './types'

const SECRET = 'the-same-secret-in-every-realm'

const service = (): Client => ({
  clientId: 'svc',
  clientSecret: SECRET,
  redirectUris: [],
  grantTypes: ['client_credentials'],
  responseTypes: [],
  scopes: ['orders'],
  tokenEndpointAuthMethod: 'client_secret_basic',
  createdAt: new Date(),
  updatedAt: new Date()
})

/** One store for the records, one adapter per realm: what `provision` would create and `retire` drop. */
const setup = async (overrides: Partial<RealmsConfig> = {}) => {
  const control = await memoryAdapter({})
  const storage = new Map<string, Adapter>()
  const configured: string[] = []
  const audits: AuditEvent[] = []
  const options: RealmsConfig = {
    store: control.realms as NonNullable<Adapter['realms']>,
    realmOf: request => new URL(request.url).hostname.match(/^([^.]+)\.id\.test$/)?.[1],
    configure: async (realm: Realm): Promise<ProviderConfig> => {
      configured.push(realm.id)
      return {
        issuer: `https://${realm.id}.id.test`,
        adapter: storage.get(realm.id) as Adapter,
        interactionUrl: `https://${realm.id}.id.test/interaction`
      }
    },
    provision: async realm => {
      const adapter = await memoryAdapter({ keys: staticKeyStore([await generateKey('ES256'), await generateKey('RS256')]) })
      await adapter.clients.upsert?.(service())
      storage.set(realm.id, adapter)
    },
    retire: async realm => {
      storage.delete(realm.id)
    },
    onAudit: event => {
      audits.push(event)
    },
    ...overrides
  }
  return { realms: createRealms(options), options, storage, configured, audits }
}

const at = (realm: string, path = '/.well-known/openid-configuration', init?: RequestInit) =>
  new Request(`https://${realm}.id.test${path}`, init)

const basic = `Basic ${btoa(`svc:${SECRET}`)}`
const form = (body: Record<string, string>) => ({
  method: 'POST',
  headers: { authorization: basic, 'content-type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams(body).toString()
})

describe('realms', () => {
  test('each realm is its own issuer', async () => {
    const { realms } = await setup()
    await realms.management.create({ id: 'acme' })
    await realms.management.create({ id: 'globex' })
    for (const id of ['acme', 'globex']) {
      const request = at(id)
      const provider = await realms.resolve(request)
      expect((await (await (provider as NonNullable<typeof provider>).handle(request)).json()).issuer).toBe(`https://${id}.id.test`)
    }
  })

  // The worst case for isolation: the same client id and secret registered in both realms.
  test('a token from one realm is nothing in another, even for a client with the same credentials', async () => {
    const { realms } = await setup()
    await realms.management.create({ id: 'acme' })
    await realms.management.create({ id: 'globex' })
    const acme = await realms.get('acme')
    const globex = await realms.get('globex')
    const issued = await (await acme?.handle(at('acme', '/token', form({ grant_type: 'client_credentials' }))))?.json()
    expect(issued.access_token).toBeTruthy()

    const here = await (await acme?.handle(at('acme', '/introspect', form({ token: issued.access_token }))))?.json()
    const there = await (await globex?.handle(at('globex', '/introspect', form({ token: issued.access_token }))))?.json()
    expect(here.active).toBe(true)
    expect(there).toEqual({ active: false })
  })

  test('each realm signs with its own keys', async () => {
    const { realms } = await setup()
    await realms.management.create({ id: 'acme' })
    await realms.management.create({ id: 'globex' })
    const kids = async (id: string) => {
      const provider = await realms.get(id)
      if (!provider) throw new Error(`realm ${id} did not resolve`)
      const { keys } = (await (await provider.handle(at(id, '/jwks'))).json()) as { keys: { kid: string }[] }
      return keys.map(key => key.kid)
    }
    const globex = await kids('globex')
    expect((await kids('acme')).filter(kid => globex.includes(kid))).toEqual([])
  })

  // generatedKeyStore() keeps one RSA key per process, so two realms built on it would verify each other's tokens.
  test('two realms sharing a signing key are refused rather than served', async () => {
    const { options, storage } = await setup()
    const careless = createRealms({
      ...options,
      provision: async realm => {
        storage.set(realm.id, await memoryAdapter({ keys: await generatedKeyStore() }))
      }
    })
    await careless.management.create({ id: 'acme' })
    await careless.management.create({ id: 'globex' })
    expect(await careless.get('acme')).toBeDefined()
    await expect(careless.get('globex')).rejects.toThrow(/acme and globex share signing key/)
  })

  // NFR-S6: a request selects a realm; it never makes one, whatever its Host says.
  test('a name that is not a realm, or not a DNS label, resolves to nothing without building anything', async () => {
    const { realms, configured } = await setup()
    expect(await realms.resolve(at('nobody'))).toBeUndefined()
    expect(await realms.get('evil.example/x')).toBeUndefined()
    expect(await realms.resolve(new Request('https://elsewhere.test/'))).toBeUndefined()
    expect(configured).toEqual([])
  })

  test('concurrent requests for a cold realm build it once', async () => {
    const { realms, configured } = await setup()
    await realms.management.create({ id: 'acme' })
    const providers = await Promise.all(Array.from({ length: 10 }, () => realms.get('acme')))
    expect(new Set(providers).size).toBe(1)
    expect(configured).toEqual(['acme'])
  })

  test('a configure that fails is not remembered', async () => {
    let fail = true
    const { realms, options } = await setup()
    const configure = options.configure
    const flaky = createRealms({
      ...options,
      configure: async realm => {
        if (fail) throw new Error('database down')
        return configure(realm)
      }
    })
    await realms.management.create({ id: 'acme' })
    await expect(flaky.get('acme')).rejects.toThrow('database down')
    fail = false
    expect(await flaky.get('acme')).toBeDefined()
  })

  test('a disabled realm resolves to nothing and keeps its data; enabling it serves it again', async () => {
    const { realms, storage } = await setup()
    await realms.management.create({ id: 'acme' })
    expect(await realms.get('acme')).toBeDefined()
    await realms.management.disable('acme')
    expect(await realms.get('acme')).toBeUndefined()
    expect(storage.has('acme')).toBe(true)
    await realms.management.enable('acme')
    expect(await realms.get('acme')).toBeDefined()
  })

  test('an update rebuilds the provider from the new record', async () => {
    const { realms, configured } = await setup()
    await realms.management.create({ id: 'acme', displayName: 'Acme' })
    const before = await realms.get('acme')
    await realms.management.update('acme', { displayName: 'ACME', settings: { brand: 'red' } })
    expect((await realms.management.find('acme'))?.settings).toEqual({ brand: 'red' })
    expect(await realms.get('acme')).not.toBe(before)
    expect(configured).toEqual(['acme', 'acme'])
  })

  // forget() reaches one process; every other one notices through revalidation.
  test('another process sees a disabled realm once its cache is due', async () => {
    const { realms, options } = await setup()
    const other = createRealms({ ...options, revalidate: 0 })
    await realms.management.create({ id: 'acme' })
    expect(await other.get('acme')).toBeDefined()
    await realms.management.disable('acme')
    expect(await other.get('acme')).toBeUndefined()
  })

  // Same timestamp, different record: a write in the same millisecond, or one made in the database by hand.
  test('another process rebuilds when the record changes but its updatedAt does not', async () => {
    const { realms, options, configured } = await setup()
    const other = createRealms({ ...options, revalidate: 0 })
    const created = await realms.management.create({ id: 'acme', settings: { plan: 'free' } })
    await other.get('acme')
    await options.store.upsert({ ...created, settings: { plan: 'pro' } })
    await other.get('acme')
    expect(configured.filter(id => id === 'acme')).toHaveLength(2)
  })

  test('an unchanged realm keeps its provider across revalidation', async () => {
    const { realms, options } = await setup()
    const other = createRealms({ ...options, revalidate: 0 })
    await realms.management.create({ id: 'acme' })
    expect(await other.get('acme')).toBe(await other.get('acme'))
  })

  test('creating provisions before the realm is served, and refuses an id that exists', async () => {
    let seenDuringProvision: unknown = 'not called'
    const { realms, options } = await setup()
    const provision = options.provision
    const watched = createRealms({
      ...options,
      provision: async realm => {
        seenDuringProvision = await watched.get(realm.id)
        await provision?.(realm)
      }
    })
    await watched.management.create({ id: 'acme' })
    expect(seenDuringProvision).toBeUndefined()
    expect(await watched.get('acme')).toBeDefined()
    await expect(realms.management.create({ id: 'acme' })).rejects.toThrow(/already exists/)
  })

  test('a provision that fails leaves no realm behind, so the id can be used again', async () => {
    const { realms, options } = await setup()
    const broken = createRealms({
      ...options,
      provision: async () => {
        throw new Error('disk full')
      }
    })
    await expect(broken.management.create({ id: 'acme' })).rejects.toThrow('disk full')
    expect(await realms.management.find('acme')).toBeUndefined()
    await realms.management.create({ id: 'acme' })
    expect(await realms.get('acme')).toBeDefined()
  })

  test('removing stops serving, retires the storage, then deletes the record', async () => {
    const { realms, storage } = await setup()
    await realms.management.create({ id: 'acme' })
    await realms.get('acme')
    await realms.management.remove('acme')
    expect(await realms.get('acme')).toBeUndefined()
    expect(storage.has('acme')).toBe(false)
    expect(await realms.management.find('acme')).toBeUndefined()
  })

  test('a retire that fails leaves the realm disabled, so the removal can be retried', async () => {
    const { realms, options } = await setup()
    const stuck = createRealms({
      ...options,
      retire: async () => {
        throw new Error('busy')
      }
    })
    await realms.management.create({ id: 'acme' })
    await expect(stuck.management.remove('acme')).rejects.toThrow('busy')
    expect((await realms.management.find('acme'))?.enabled).toBe(false)
    await realms.management.remove('acme')
    expect(await realms.management.find('acme')).toBeUndefined()
  })

  // FR-M3: every management write is audited.
  test('every write emits an audit event naming the realm', async () => {
    const { realms, audits } = await setup()
    await realms.management.create({ id: 'acme' })
    await realms.management.update('acme', { displayName: 'ACME' })
    await realms.management.disable('acme')
    await realms.management.enable('acme')
    await realms.management.remove('acme')
    expect(audits.map(event => [event.action, event.detail?.realm])).toEqual([
      ['realm.create', 'acme'],
      ['realm.update', 'acme'],
      ['realm.disable', 'acme'],
      ['realm.enable', 'acme'],
      ['realm.remove', 'acme']
    ])
  })

  test('realm ids are DNS labels', () => {
    for (const id of ['acme', 'a', 'acme-2', '0x1']) expect(isRealmId(id)).toBe(true)
    for (const id of ['', 'Acme', '-acme', 'acme-', 'a.b', 'a/b', 'a_b', 'x'.repeat(64)]) expect(isRealmId(id)).toBe(false)
  })

  test('an invalid id is refused at creation', async () => {
    const { realms } = await setup()
    await expect(realms.management.create({ id: 'Acme.Corp' })).rejects.toThrow(/DNS label/)
  })
})
