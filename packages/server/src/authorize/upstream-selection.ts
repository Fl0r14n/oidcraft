/**
 * Choosing which upstream to broker to is a decision, not I/O, so it belongs in the core (FR-F4).
 * Performing the round trip is I/O, so it does not: `oidcraft/federation` does that, driven by the
 * host, the same division as the device flow and CIBA.
 */
export type UpstreamDescriptor = {
  id: string
  label?: string
  /** Email domains this provider owns. */
  domains?: string[]
}

export type SelectionHints = {
  loginHint?: string | undefined
  acrValues?: string[] | undefined
  /** What the client restricts itself to, from `Client.upstreamProviders` (FR-F2). */
  allowed?: string[] | undefined
}

/** `acr_values` naming a provider directly, e.g. `urn:oidcraft:idp:entra`. */
export const ACR_PREFIX = 'urn:oidcraft:idp:'

const domainOf = (loginHint: string | undefined) => loginHint?.split('@')[1]?.toLowerCase()

/**
 * In order: an explicit id, then `acr_values`, then the email domain, then the single remaining
 * candidate. When none of those decides it, the candidates are returned and nobody is chosen —
 * guessing here would sign the user in somewhere they did not ask for.
 */
export const selectUpstream = <T extends UpstreamDescriptor>(providers: T[], hints: SelectionHints, explicit?: string) => {
  const allowed = hints.allowed?.length ? providers.filter(provider => hints.allowed?.includes(provider.id)) : providers

  if (explicit) {
    const chosen = allowed.find(provider => provider.id === explicit)
    return { chosen, candidates: chosen ? [chosen] : [] }
  }

  const byAcr = hints.acrValues?.length ? allowed.filter(provider => hints.acrValues?.includes(`${ACR_PREFIX}${provider.id}`)) : []
  if (byAcr.length === 1) return { chosen: byAcr[0], candidates: byAcr }

  const domain = domainOf(hints.loginHint)
  const byDomain = domain ? allowed.filter(provider => provider.domains?.includes(domain)) : []
  if (byDomain.length === 1) return { chosen: byDomain[0], candidates: byDomain }

  if (allowed.length === 1) return { chosen: allowed[0], candidates: allowed }
  return { chosen: undefined, candidates: allowed }
}
