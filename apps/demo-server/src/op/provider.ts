/// <reference types="bun" />

import { createProvider, staticKeyStore } from 'oidcraft'
import { accountStore, createDemoAccounts, seedDemoAccounts } from './accounts'
import { issuer, optional } from './env'
import { seedFirstPartyClients } from './first-party'
import { seedConformanceClients, seedDemoClient } from './seed'
import { openStorage } from './storage'
import { upstreams } from './upstreams'

/**
 * Development generates a key per process, so every restart signs everyone out. Production supplies
 * OIDCRAFT_JWKS and rotates by prepending (FR-C10, NFR-S7).
 */
const keys = () => {
  const raw = optional('OIDCRAFT_JWKS')
  if (!raw) {
    if (Bun.env.NODE_ENV === 'production') throw new Error('OIDCRAFT_JWKS is required in production')
    console.warn('[oidcraft] no OIDCRAFT_JWKS: generating a key for this process only')
    return undefined
  }
  return staticKeyStore(JSON.parse(raw))
}

const storage = await openStorage({ federation: upstreams.length > 0, keys: keys() })

export const accounts = createDemoAccounts(storage, optional('OIDCRAFT_BRAND_NAME') ?? 'oidcraft')
await seedDemoAccounts(accounts, storage)

const adapter = { ...storage, accounts: accountStore(storage, accounts) }

// Expired rows are never served (FR-T5); sweeping them only reclaims the space, in bounded batches (NFR-P3).
setInterval(() => void adapter.artifacts.prune?.(new Date(), 1000), 10 * 60_000).unref()

await seedDemoClient(adapter)
await seedFirstPartyClients(adapter, issuer())
await seedConformanceClients(adapter)

export const provider = createProvider({
  issuer: issuer(),
  adapter,
  interactionUrl: `${issuer()}/interaction`,
  // Descriptors only: the admin API lists these, and an upstream's client secret is not for it.
  upstreams: upstreams.map(({ id, label, domains }) => ({ id, ...(label && { label }), ...(domains && { domains }) })),
  // The reference deployment turns these on so the screens below have something to drive.
  features: { deviceFlow: true, pushedAuthorizationRequests: true, dpop: true }
})
