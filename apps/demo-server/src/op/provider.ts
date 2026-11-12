/// <reference types="bun" />
import { staticKeyStore } from '@oidcraft/adapter'
import { createProvider } from '@oidcraft/provider'
import { seedFapiDemoClient } from '../fapi/demo'
import { screens } from '../interaction/screens'
import { mcpEnabled, mcpResources, resolveClientMetadata, seedMcpResourceServer } from '../mcp/server'
import { accountStore, createDemoAccounts, seedDemoAccounts } from './accounts'
import { issuer, optional } from './env'
import { seedFirstPartyClients } from './first-party'
import { forgettingConsent } from './forget-consent'
import { seedConformanceClients, seedDemoClient, seedFapiConformanceClients } from './seed'
import type { Site } from './site'
import { openStorage, storageLocation } from './storage'
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

const storage = await openStorage({ keys: keys() })

export const accounts = createDemoAccounts(storage, optional('OIDCRAFT_BRAND_NAME') ?? 'oidcraft')
await seedDemoAccounts(accounts, storage)

// The FAPI conformance run asks consent on every authorization, so the module in which the user refuses
// always has a screen to refuse on, whatever session the module before it left (conformance/README.md).
const forgetConsent = optional('OIDCRAFT_FORGET_CONSENT') === 'on'
if (forgetConsent && storageLocation() !== 'memory') {
  // A fresh consent writes a second grant for the pair, which the SQL schemas' unique index refuses.
  throw new Error('OIDCRAFT_FORGET_CONSENT=on needs OIDCRAFT_DB=memory: it is for the FAPI conformance run only')
}

const withAccounts = { ...storage, accounts: accountStore(storage, accounts) }
const adapter = forgetConsent ? forgettingConsent(withAccounts) : withAccounts

// Expired rows are never served (FR-T5); sweeping them only reclaims the space, in bounded batches (NFR-P3).
const sweep = async () => {
  const now = new Date()
  await adapter.artifacts.prune?.(now, 1000)
  await adapter.sessions.prune?.(now, 1000)
  await adapter.replay.prune?.(now, 1000)
}
setInterval(() => void sweep().catch(error => console.error('[prune]', error)), 10 * 60_000).unref()

await seedDemoClient(adapter)
await seedFirstPartyClients(adapter, issuer())
await seedConformanceClients(adapter)
await seedFapiConformanceClients(adapter)
await seedFapiDemoClient(adapter, issuer())
await seedMcpResourceServer(adapter)

// OIDCRAFT_PROFILE=fapi2 puts every client under FAPI 2.0, as its conformance plan expects (FR-C21).
// Off, only the FAPI demo client is, beside the public ones.
const profile = optional('OIDCRAFT_PROFILE')

export const provider = createProvider({
  issuer: issuer(),
  adapter,
  ...(profile && { profile: profile as 'fapi2' }),
  interactionUrl: `${issuer()}/interaction`,
  // Descriptors only: the admin API lists these, and an upstream's client secret is not for it.
  upstreams: upstreams.map(({ id, label, domains }) => ({ id, ...(label && { label }), ...(domains && { domains }) })),
  // The reference deployment turns these on so the screens below have something to drive.
  features: { deviceFlow: true, pushedAuthorizationRequests: true, dpop: true, dynamicRegistration: mcpEnabled },
  // An MCP client registers itself, or names a metadata document it serves (FR-C9, FR-C20).
  ...(mcpEnabled && { resources: mcpResources(), resolveClientMetadata })
})

/** The issuer at OIDCRAFT_ISSUER. With realms on, it is the control plane the operator signs in through. */
export const control: Site = { provider, accounts, screens, brokering: upstreams.length > 0 }

export { adapter as controlAdapter }
