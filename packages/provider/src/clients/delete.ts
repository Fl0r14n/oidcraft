import type { ResolvedConfig } from '../config'

/** FR-T7: a client goes with the tokens and the consents it holds, or they outlive anyone who could revoke them. */
export const deleteClient = async (config: ResolvedConfig, clientId: string) => {
  await config.adapter.artifacts.revokeByClientId(clientId)
  await config.adapter.grants.destroyByClientId(clientId)
  await config.adapter.clients.destroy?.(clientId)
}
