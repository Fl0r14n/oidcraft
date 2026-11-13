import { randomString } from '@oidcraft/core'
import type { ResolvedConfig } from '../config'

/** FR-I4: one grant per account and client, which every consent adds to; the store merges atomically, so none is lost to another. */
export const recordConsent = (config: ResolvedConfig, accountId: string, clientId: string, scopes: string[], claims: string[] = []) =>
  config.adapter.grants.merge({ id: randomString(), accountId, clientId, scopes, claims, resources: {}, createdAt: new Date() })
