import type { Grant } from './types'

/** What a consent adds to the grant it lands on: its scopes, claims and resources, never fewer (FR-I4). */
export const mergedGrant = (held: Grant, grant: Grant): Grant => ({
  ...held,
  scopes: [...new Set([...held.scopes, ...grant.scopes])],
  claims: [...new Set([...held.claims, ...grant.claims])],
  resources: { ...held.resources, ...grant.resources }
})

/** A grant past its `expiresAt` is gone: a consent after it starts a new grant, so the old one's tokens stay dead (FR-T5). */
export const grantExpired = (grant: Pick<Grant, 'expiresAt'>, now = Date.now()) =>
  grant.expiresAt !== undefined && grant.expiresAt.getTime() <= now

/** How many times a compare-and-swap merge rereads before it gives up: each lost round is another consent landing. */
export const MERGE_ROUNDS = 16
