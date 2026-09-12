/// <reference types="bun" />

import { createProvider, staticKeyStore } from 'oidcraft'
import { memoryAdapter } from 'oidcraft/adapters/memory'
import { issuer, optional } from './env'

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

export const provider = createProvider({
  issuer: issuer(),
  adapter: await memoryAdapter(keyStore ? { keys: keyStore } : {}),
  interactionUrl: `${issuer()}/interaction`
})
