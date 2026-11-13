import type { Grant } from '@oidcraft/adapter'
import { randomString } from '@oidcraft/core'
import type { ResolvedConfig } from '../config'

/**
 * Adds what was just consented to the one grant per account and client (FR-I4), and returns it as
 * stored: a first consent racing another may have been written into that one's grant.
 */
export const recordConsent = async (config: ResolvedConfig, accountId: string, clientId: string, scopes: string[]) => {
  const previous = await config.adapter.grants.findByAccountAndClient(accountId, clientId)
  const grant: Grant = {
    id: previous?.id ?? randomString(),
    accountId,
    clientId,
    scopes: [...new Set([...(previous?.scopes ?? []), ...scopes])],
    claims: previous?.claims ?? [],
    resources: previous?.resources ?? {},
    createdAt: previous?.createdAt ?? new Date()
  }
  await config.adapter.grants.upsert(grant)
  return (await config.adapter.grants.findByAccountAndClient(accountId, clientId)) ?? grant
}
