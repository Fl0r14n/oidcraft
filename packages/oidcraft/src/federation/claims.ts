import type { ClaimMapper } from './types'

/**
 * Nothing from an upstream becomes a local claim without a mapper saying so (FR-F7). `sub` is never
 * among them: it is the upstream's subject and is meaningful only within that upstream, so a local
 * subject is derived from `(provider, subject)` instead (ARCHITECTURE.md §5.4).
 */
const NEVER_MAPPED = new Set(['sub', 'iss', 'aud', 'exp', 'iat', 'nbf', 'jti', 'azp', 'at_hash', 'c_hash', 'nonce'])

export const standardClaims = ['name', 'given_name', 'family_name', 'preferred_username', 'email', 'email_verified', 'picture', 'locale']

export const pickClaims =
  (allowed: string[] = standardClaims): ClaimMapper =>
  upstream =>
    Object.fromEntries(
      Object.entries(upstream).filter(([key, value]) => allowed.includes(key) && !NEVER_MAPPED.has(key) && value !== undefined)
    )

export const renameClaims =
  (mapping: Record<string, string>, base: ClaimMapper = pickClaims()): ClaimMapper =>
  upstream => {
    const mapped = base(upstream)
    for (const [from, to] of Object.entries(mapping)) {
      if (NEVER_MAPPED.has(to)) continue
      if (upstream[from] !== undefined) mapped[to] = upstream[from]
    }
    return mapped
  }

/** A stable local subject for a brokered identity; an upstream `sub` is unique only within it. */
export const localSubject = (provider: string, subject: string) => `${provider}:${subject}`
