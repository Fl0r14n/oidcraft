import type { ResolvedConfig } from '../config'

/** FR-T7: a client goes with the tokens and the consents it holds, or they outlive anyone who could revoke them. */
export const deleteClient = async (config: ResolvedConfig, clientId: string) => {
  // Grants first, as a revocation goes: a redemption already past its checks then finds its grant gone (FR-T3).
  await config.adapter.grants.destroyByClientId(clientId)
  await config.adapter.artifacts.revokeByClientId(clientId)
  await config.adapter.clients.destroy?.(clientId)
}
