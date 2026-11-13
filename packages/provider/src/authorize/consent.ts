import type { Grant } from '@oidcraft/adapter'
import { randomString } from '@oidcraft/core'
import type { ResolvedConfig } from '../config'

/** Each round answers a write that raced this one; past a few, a scope still missing is asked for again, never granted. */
const ROUNDS = 5

/**
 * Adds what was just consented to the one grant per account and client (FR-I4), and returns it as
 * stored. A first consent racing another may land in that one's grant and lose its scopes to it, so
 * it is read back and written again until it holds what was consented.
 */
export const recordConsent = async (config: ResolvedConfig, accountId: string, clientId: string, scopes: string[]) => {
  const find = () => config.adapter.grants.findByAccountAndClient(accountId, clientId)
  let previous = await find()
  let grant: Grant | undefined
  for (let round = 0; round < ROUNDS; round++) {
    grant = {
      id: previous?.id ?? randomString(),
      accountId,
      clientId,
      scopes: [...new Set([...(previous?.scopes ?? []), ...scopes])],
      claims: previous?.claims ?? [],
      resources: previous?.resources ?? {},
      createdAt: previous?.createdAt ?? new Date()
    }
    await config.adapter.grants.upsert(grant)
    const stored = await find()
    if (!stored || scopes.every(scope => stored.scopes.includes(scope))) return stored ?? grant
    previous = stored
  }
  return previous ?? (grant as Grant)
}
