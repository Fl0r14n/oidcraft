import { grantManagement } from './authorize/management'
import { clientManagement } from './clients/management'
import type { ResolvedConfig } from './config'
import { keyManagement } from './keys/management'
import { sessionManagement } from './session/management'
import { identityManagement, upstreamManagement } from './upstreams/management'

export type { ManagementClientInput } from './clients/management'

/**
 * The operator surface over clients, grants, sessions and keys (FR-M1). It performs no authorization: mount it
 * behind your own admin authentication. Every write emits an audit event for the host to route (FR-M3).
 */
export const management = (config: ResolvedConfig) => ({
  clients: clientManagement(config),
  grants: grantManagement(config),
  sessions: sessionManagement(config),
  keys: keyManagement(config),
  upstreams: upstreamManagement(config),
  identities: identityManagement(config)
})

export type Management = ReturnType<typeof management>
