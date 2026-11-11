import type { FullAdapter } from '@oidcraft/adapter'

/**
 * Storage that remembers a consent only until it yields a code, so the next authorization asks again.
 * For the FAPI conformance run alone: its browser keeps one session across modules, and the module in
 * which the user refuses needs a screen to refuse on (conformance/README.md). A real deployment
 * remembers consent (FR-I4).
 */
export const forgettingConsent = <A extends FullAdapter>(adapter: A): A => {
  // The resumed authorization reads the grant its consent just wrote, so only a spent one is hidden.
  const spent = new Set<string>()
  return {
    ...adapter,
    artifacts: {
      ...adapter.artifacts,
      async upsert(artifact) {
        if (artifact.kind === 'authorization_code' && artifact.grantId) spent.add(artifact.grantId)
        return adapter.artifacts.upsert(artifact)
      }
    },
    grants: {
      ...adapter.grants,
      // A consent after a spent one writes a second grant for the pair; the lookup must find the new one.
      async findByAccountAndClient(accountId, clientId) {
        const held = await adapter.grants.listForAccount(accountId)
        return held.find(grant => grant.clientId === clientId && !spent.has(grant.id))
      }
    }
  }
}
