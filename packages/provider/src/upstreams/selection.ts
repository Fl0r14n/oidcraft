import type { ResolvedConfig } from '../config'
/**
 * An upstream as home-realm discovery sees it (FR-F4). Choosing is a decision, so the core makes it;
 * the round trip is I/O, so `@oidcraft/provider/broker` makes it, driven by the host.
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

/** FR-C23: the configured levels, and an `acr` naming each upstream, which home-realm discovery accepts (FR-F4). */
export const supportedAcrValues = (config: Pick<ResolvedConfig, 'acrValues' | 'upstreams'>) =>
  config.acrValues && [...config.acrValues, ...config.upstreams.map(upstream => `${ACR_PREFIX}${upstream.id}`)]

const domainOf = (loginHint: string | undefined) => loginHint?.split('@')[1]?.toLowerCase()

/** An explicit id, then `acr_values`, then the email domain, then a sole candidate; otherwise the candidates, never a guess. */
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
