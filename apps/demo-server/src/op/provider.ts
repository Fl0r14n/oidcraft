/// <reference types="bun" />
import { createProvider, staticKeyStore } from 'oidcraft'
import { seedFapiDemoClient } from '../fapi/demo'
import { screens } from '../interaction/screens'
import { mcpEnabled, mcpResources, resolveClientMetadata, seedMcpResourceServer } from '../mcp/server'
import { accountStore, createDemoAccounts, seedDemoAccounts } from './accounts'
import { issuer, optional } from './env'
import { seedFirstPartyClients } from './first-party'
import { seedConformanceClients, seedDemoClient, seedFapiConformanceClients } from './seed'
import type { Site } from './site'
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

const storage = await openStorage({ keys: keys() })

export const accounts = createDemoAccounts(storage, optional('OIDCRAFT_BRAND_NAME') ?? 'oidcraft')
await seedDemoAccounts(accounts, storage)

const adapter = { ...storage, accounts: accountStore(storage, accounts) }

// Expired rows are never served (FR-T5); sweeping them only reclaims the space, in bounded batches (NFR-P3).
setInterval(() => void adapter.artifacts.prune?.(new Date(), 1000), 10 * 60_000).unref()

await seedDemoClient(adapter)
await seedFirstPartyClients(adapter, issuer())
await seedConformanceClients(adapter)
await seedFapiConformanceClients(adapter)
await seedFapiDemoClient(adapter, issuer())
await seedMcpResourceServer(adapter)

// OIDCRAFT_PROFILE=fapi2 puts every client under FAPI 2.0, as its conformance plan expects (FR-C21).
// Off, only the FAPI demo client is, beside the public ones.
const profile = optional('OIDCRAFT_PROFILE')
// The FAPI conformance run sets a few seconds, so each module starts signed out and has a sign-in to cancel.
const sessionTtl = optional('OIDCRAFT_SESSION_TTL')

export const provider = createProvider({
  issuer: issuer(),
  adapter,
  ...(profile && { profile: profile as 'fapi2' }),
  ...(sessionTtl && { ttl: { session: Number(sessionTtl) } }),
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
