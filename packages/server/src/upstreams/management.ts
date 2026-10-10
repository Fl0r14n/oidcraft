import { audit } from '../audit'
import type { ResolvedConfig } from '../config'

export const upstreamManagement = (config: ResolvedConfig) => ({
  /**
   * Read-only on purpose. Upstreams are deployment configuration — an issuer and client
   * credentials — not runtime state, so they are set where the rest of the deployment is set
   * and an operator screen shows what is configured rather than editing it (FR-M2).
   */
  list() {
    return config.upstreams
  }
})

export const identityManagement = (config: ResolvedConfig) => ({
  async listForAccount(accountId: string) {
    return config.adapter.identities?.listForAccount(accountId) ?? []
  },
  async unlink(accountId: string, provider: string) {
    await config.adapter.identities?.unlink(accountId, provider)
    await audit(config, 'identity.unlink', { accountId, detail: { provider } })
  }
})
