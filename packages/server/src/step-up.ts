import type { Artifact } from './types'

export type StepUpRequirement = {
  /** The authentication strength the resource needs, e.g. `mfa`. */
  acrValues?: string[]
  /** How recently the user must have authenticated, in seconds. */
  maxAge?: number
}

export type StepUpVerdict = { sufficient: true } | { sufficient: false; challenge: string }

/**
 * The resource-server half of step-up (RFC 9470, FR-C16).
 *
 * The provider honours `acr_values` on the way in; this is how a resource server *asks* for that to
 * happen. Returning 403 with no challenge tells the client it failed but not what would succeed,
 * which is why the header carries the requirement rather than only the error.
 *
 * The token's own `acr` is not consulted from the JWT: this reads the stored artifact and the
 * session behind it, so a client cannot re-present an old token with a rewritten claim.
 */
export const meetsRequirement = (
  requirement: StepUpRequirement,
  actual: { acr?: string | undefined; authTime?: Date | undefined }
): StepUpVerdict => {
  const parts: string[] = ['Bearer error="insufficient_user_authentication"']

  const acrUnmet = Boolean(requirement.acrValues?.length && (!actual.acr || !requirement.acrValues.includes(actual.acr)))
  const staleness = actual.authTime ? (Date.now() - actual.authTime.getTime()) / 1000 : Number.POSITIVE_INFINITY
  const ageUnmet = requirement.maxAge !== undefined && staleness > requirement.maxAge

  if (!acrUnmet && !ageUnmet) return { sufficient: true }

  if (acrUnmet) {
    parts.push(`acr_values="${requirement.acrValues?.join(' ')}"`)
    parts.push('error_description="a stronger authentication is required"')
  }
  if (ageUnmet) {
    parts.push(`max_age="${requirement.maxAge}"`)
    if (!acrUnmet) parts.push('error_description="a more recent authentication is required"')
  }

  return { sufficient: false, challenge: parts.join(', ') }
}

/** What a resource server knows about the authentication behind a token it is holding. */
export const authenticationOf = (artifact: Artifact, session: { acr?: string | undefined; authTime: Date } | undefined) => ({
  acr: session?.acr,
  authTime: session?.authTime,
  accountId: artifact.accountId
})
