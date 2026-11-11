import type { ClaimMapper } from './types'

/**
 * Nothing from an upstream becomes a local claim without a mapper saying so (FR-F7). `sub` is never
 * among them: it is the upstream's subject and is meaningful only within that upstream, so a local
 * subject is derived from `(provider, subject)` instead (ARCHITECTURE.md §5.4).
 */
const NEVER_MAPPED = new Set([
  'sub',
  'iss',
  'aud',
  'exp',
  'iat',
  'nbf',
  'jti',
  'azp',
  'at_hash',
  'c_hash',
  'nonce',
  // How and where the user signed in is the session's to record, from the upstream's token, never a
  // profile claim an upstream or a mapper can set (FR-F6).
  'acr',
  'amr',
  'auth_time',
  'sid',
  'idp',
  'cnf'
])

/** A verification flag describes one value; paired with another, it vouches for an address nobody checked. */
const VERIFIED_BY = { email: 'email_verified', phone_number: 'phone_number_verified' } as const

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
    // FR-F5, NFR-S8: when a value came from another source, the upstream's flag for it does not
    // apply — unless the mapping names where that value's own flag comes from.
    for (const [claim, flag] of Object.entries(VERIFIED_BY)) {
      const source = Object.entries(mapping).find(([, to]) => to === claim)?.[0]
      const flagSource = Object.entries(mapping).find(([, to]) => to === flag)?.[0]
      if (source !== undefined && source !== claim && flagSource === undefined) delete mapped[flag]
    }
    return mapped
  }

/** A stable local subject for a brokered identity; an upstream `sub` is unique only within it. */
export const localSubject = (provider: string, subject: string) => `${provider}:${subject}`
