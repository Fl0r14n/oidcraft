import { audit } from '../audit'
import type { ResolvedConfig } from '../config'

export const grantManagement = (config: ResolvedConfig) => ({
  async listForAccount(accountId: string) {
    return config.adapter.grants.listForAccount(accountId)
  },

  /** Revoking consent must take the tokens with it, or "revoked" is a label on nothing. */
  async revoke(grantId: string) {
    // The grant goes first: a token written after the sweep finds it gone (`assertFamilyLive`).
    await config.adapter.grants.destroy(grantId)
    await config.adapter.artifacts.revokeByGrantId(grantId)
    await audit(config, 'grant.revoke', { grantId })
  }
})
