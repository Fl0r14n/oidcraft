import { audit } from '../audit'
import type { ResolvedConfig } from '../config'

export const upstreamManagement = (config: ResolvedConfig) => ({
  /** Read-only on purpose: upstreams are deployment configuration, not runtime state (FR-M2). */
  list() {
    return config.upstreams
  }
})

export const identityManagement = (config: ResolvedConfig) => ({
  async listForAccount(accountId: string) {
    return config.adapter.identities?.listForAccount(accountId) ?? []
  },
  async unlink(accountId: string, upstream: string) {
    const linked = (await config.adapter.identities?.listForAccount(accountId)) ?? []
    for (const identity of linked) {
      if (identity.upstream === upstream) await config.adapter.identities?.destroy(identity.upstream, identity.subject)
    }
    await audit(config, 'identity.unlink', { accountId, detail: { upstream } })
  }
})
