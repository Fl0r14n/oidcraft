import type { UpstreamProvider } from './types'

export type SelectionHints = {
  loginHint?: string | undefined
  acrValues?: string[] | undefined
  /** What the client is allowed to broker to, from `Client.upstreamProviders` (FR-F2). */
  allowed?: string[] | undefined
}

const domainOf = (loginHint: string | undefined) => loginHint?.split('@')[1]?.toLowerCase()

/**
 * Home-realm discovery (FR-F4), in order: an explicit id, then `acr_values`, then the email domain,
 * then — only when exactly one remains — the single candidate. Otherwise the user is asked, which
 * is why this returns a list rather than guessing.
 */
export const selectUpstream = (providers: UpstreamProvider[], hints: SelectionHints, explicit?: string) => {
  const allowed = hints.allowed?.length ? providers.filter(provider => hints.allowed?.includes(provider.id)) : providers

  if (explicit) {
    const chosen = allowed.find(provider => provider.id === explicit)
    return { chosen, candidates: chosen ? [chosen] : [] }
  }

  const byAcr = hints.acrValues?.length ? allowed.filter(provider => hints.acrValues?.includes(`urn:oidcraft:idp:${provider.id}`)) : []
  if (byAcr.length === 1) return { chosen: byAcr[0], candidates: byAcr }

  const domain = domainOf(hints.loginHint)
  const byDomain = domain ? allowed.filter(provider => provider.domains?.includes(domain)) : []
  if (byDomain.length === 1) return { chosen: byDomain[0], candidates: byDomain }

  if (allowed.length === 1) return { chosen: allowed[0], candidates: allowed }
  return { chosen: undefined, candidates: allowed }
}
