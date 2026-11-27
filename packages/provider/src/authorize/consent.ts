import type { Grant } from '@oidcraft/adapter'
import { randomString } from '@oidcraft/core'
import type { ResolvedConfig } from '../config'
import { OAuthError } from '../errors'
import type { AuthorizationRequest } from './authorization'
import { heldClaims, individuallyRequested } from './claims'

/** FR-I4: one grant per account and client, which every consent adds to; the store merges atomically, so none is lost to another. */
export const recordConsent = (config: ResolvedConfig, accountId: string, clientId: string, scopes: string[], claims: string[] = []) =>
  config.adapter.grants.merge({ id: randomString(), accountId, clientId, scopes, claims, resources: {}, createdAt: new Date() })

type Asked = Pick<AuthorizationRequest, 'scopes' | 'claims'>
type Covering = Pick<Grant, 'scopes' | 'claims'> | undefined

/** FR-I4, FR-C22: what the request asks for that none of the grants or consents given covers. */
export const outstandingConsent = (config: ResolvedConfig, request: Asked, ...given: Covering[]) => {
  const scopes = new Set(given.flatMap(each => each?.scopes ?? []))
  const claims = new Set(given.flatMap(each => [...heldClaims(config, each)]))
  return {
    scopes: request.scopes.filter(scope => !scopes.has(scope)),
    claims: individuallyRequested(config, request.scopes, request.claims).filter(name => !claims.has(name))
  }
}

const refuse = (description: string, spec: string) => new OAuthError('invalid_request', { description, spec })

/** All or nothing, and nothing unasked: a partial consent would be stored, then asked for again in full (FR-I4, FR-C22). */
export const assertConsentCovers = (
  config: ResolvedConfig,
  request: Asked,
  held: Covering,
  consent: { scopes: string[]; claims?: string[] | undefined }
) => {
  const unasked = consent.scopes.filter(scope => !request.scopes.includes(scope))
  if (unasked.length) throw refuse(`consent grants ${unasked.join(', ')}, which this request did not ask for`, 'FR-I4')
  const asked = individuallyRequested(config, request.scopes, request.claims)
  const unaskedClaims = (consent.claims ?? []).filter(name => !asked.includes(name))
  if (unaskedClaims.length) {
    throw refuse(`consent grants the claims ${unaskedClaims.join(', ')}, which this request did not ask for`, 'FR-C22')
  }
  const outstanding = outstandingConsent(config, request, held, { scopes: consent.scopes, claims: consent.claims ?? [] })
  if (outstanding.scopes.length) {
    throw refuse(
      `consent must approve every requested scope, or answer access_denied; it leaves out ${outstanding.scopes.join(', ')}`,
      'FR-I4'
    )
  }
  if (outstanding.claims.length) {
    throw refuse(
      `consent must approve every requested claim, or answer access_denied; it leaves out ${outstanding.claims.join(', ')}`,
      'FR-C22'
    )
  }
}
