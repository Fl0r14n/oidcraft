import type { FullAdapter } from '@oidcraft/adapter'

/** FAPI conformance run only, so its refusal module gets a consent screen (conformance/README.md); a real OP remembers (FR-I4). */
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
      // A consent is merged into the pair's one grant (FR-I4), which makes a spent grant current again.
      async merge(grant) {
        const stored = await adapter.grants.merge(grant)
        spent.delete(stored.id)
        return stored
      },
      async findByAccountAndClient(accountId, clientId) {
        const grant = await adapter.grants.findByAccountAndClient(accountId, clientId)
        return grant && !spent.has(grant.id) ? grant : undefined
      }
    }
  }
}
