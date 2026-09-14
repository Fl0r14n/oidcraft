/// <reference types="bun" />

import { createProvider, staticKeyStore } from 'oidcraft'
import { memoryAdapter } from 'oidcraft/adapters/memory'
import { issuer, optional } from './env'
import { demoAccounts, seedDemoClient } from './seed'

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

const keyStore = keys()
const adapter = await memoryAdapter({ accounts: demoAccounts, ...(keyStore && { keys: keyStore }) })

await seedDemoClient(adapter)

export const provider = createProvider({
  issuer: issuer(),
  adapter,
  interactionUrl: `${issuer()}/interaction`,
  // The reference deployment turns these on so the screens below have something to drive.
  features: { deviceFlow: true, pushedAuthorizationRequests: true, dpop: true }
})
