/// <reference types="bun" />
import { type ActiveKey, type Adapter, createRealms, generateKey, type Realm, staticKeyStore } from 'oidcraft'
import { screensFor } from '../interaction/screens'
import { accountStore, createDemoAccounts } from './accounts'
import { issuer, optional } from './env'
import { control, controlAdapter } from './provider'
import { seedDemoClient } from './seed'
import type { Site } from './site'
import { openAdapter, storageLocation } from './storage'

/** Off unless OIDCRAFT_REALMS=on: the demo is one issuer, as most deployments are (FR-M4). */
export const realmsEnabled = optional('OIDCRAFT_REALMS') === 'on'

const controlUrl = new URL(issuer())

/** `acme.localhost:3001` names the realm `acme`; the control host itself names none. */
const realmOf = (request: Request) => {
  const { host } = new URL(request.url)
  const suffix = `.${controlUrl.host}`
  return host.endsWith(suffix) ? host.slice(0, -suffix.length) : undefined
}

export const realmIssuer = (id: string) => `${controlUrl.protocol}//${id}.${controlUrl.host}`

const memory = storageLocation() === 'memory'
// Beside the control plane's database: data/oidcraft.sqlite keeps its realms in data/realms/.
const directory = `${storageLocation().replace(/[^/]*$/, '')}realms`
const file = (id: string, extension: string) => `${directory}/${id}.${extension}`

// Each realm's own keys, never generatedKeyStore(): its RSA key is one per process, and createRealms
// refuses two realms that share a signing key.
const keysInMemory = new Map<string, ActiveKey[]>()
const readKeys = async (id: string): Promise<ActiveKey[]> =>
  memory ? (keysInMemory.get(id) ?? []) : JSON.parse(await Bun.file(file(id, 'jwks.json')).text())
const writeKeys = async (id: string, keys: ActiveKey[]) => {
  if (memory) keysInMemory.set(id, keys)
  else await Bun.write(file(id, 'jwks.json'), JSON.stringify(keys))
}

const storages = new Map<string, Adapter>()
const storageOf = async (id: string) => {
  let storage = storages.get(id)
  if (!storage) {
    storage = await openAdapter(memory ? 'memory' : file(id, 'sqlite'), { federation: false, keys: staticKeyStore(await readKeys(id)) })
    storages.set(id, storage)
  }
  return storage
}

const sites = new Map<string, Omit<Site, 'provider'>>()

export const realms = realmsEnabled
  ? createRealms({
      store: controlAdapter.realms as NonNullable<Adapter['realms']>,
      realmOf,
      configure: async (realm: Realm) => {
        const storage = await storageOf(realm.id)
        const name = realm.displayName ?? realm.id
        const accounts = createDemoAccounts(storage, name)
        sites.set(realm.id, { accounts, screens: screensFor(name, realmIssuer(realm.id)), federation: false })
        return {
          issuer: realmIssuer(realm.id),
          adapter: { ...storage, accounts: accountStore(storage, accounts) },
          interactionUrl: `${realmIssuer(realm.id)}/interaction`,
          features: { deviceFlow: true, pushedAuthorizationRequests: true, dpop: true }
        }
      },
      // The host's half of the lifecycle: storage and keys exist before the realm is served.
      provision: async realm => {
        await writeKeys(realm.id, [await generateKey('ES256'), await generateKey('RS256')])
        await seedDemoClient(await storageOf(realm.id))
      },
      retire: async realm => {
        storages.delete(realm.id)
        sites.delete(realm.id)
        keysInMemory.delete(realm.id)
        if (memory) return
        for (const extension of ['sqlite', 'sqlite-wal', 'sqlite-shm', 'jwks.json']) {
          const target = Bun.file(file(realm.id, extension))
          if (await target.exists()) await target.delete()
        }
      },
      onAudit: event => console.log(`[audit] ${event.action} ${event.detail?.realm}`)
    })
  : undefined

/**
 * The site a request is for: the control plane on its own host, a realm on a subdomain of it, and
 * undefined for a subdomain that names no enabled realm.
 */
export const siteOf = async (request: Request): Promise<Site | undefined> => {
  if (!realms) return control
  const id = realmOf(request)
  if (id === undefined) return control
  const provider = await realms.get(id)
  const rest = sites.get(id)
  return provider && rest ? { provider, ...rest } : undefined
}
