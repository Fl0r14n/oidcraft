import { grantManagement } from './authorize/management'
import { clientManagement } from './clients/management'
import type { ResolvedConfig } from './config'
import { keyManagement } from './keys/management'
import { sessionManagement } from './session/management'
import { identityManagement, upstreamManagement } from './upstreams/management'

export type { ManagementClientInput } from './clients/management'

/**
 * The operator-facing surface over clients, grants, sessions and keys (FR-M1).
 *
 * **This performs no authorization.** It is a set of functions, not an HTTP endpoint, precisely so
 * that mounting it is a deliberate act: the host puts it behind its own admin authentication and
 * the library never has to guess who counts as an administrator. Every write emits an audit event
 * the host routes somewhere; the library persists none of them (FR-M3).
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
