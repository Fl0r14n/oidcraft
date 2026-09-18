import { describe, expect, test } from 'bun:test'
import { applyDiscovery, type OpenIdConfiguration } from '@oidcraft/core'
import { memoryAdapter } from './adapters/memory'
import { resolveConfig } from './config'
import { metadata } from './endpoints/discovery'

/**
 * The one place the OP half and the relying-party half of this workspace are pinned to each other.
 *
 * They are the same protocol from opposite ends and cannot share a single type: `metadata` *writes*
 * the document and wants its members required, `OpenIdConfiguration` *reads* one and must tolerate
 * a provider that omits anything. What can be shared is the assertion that every member the reader
 * looks for is one the writer emits — so the day an endpoint is renamed here, it is a compile error
 * rather than an `undefined` in somebody's client six months later.
 */
const ISSUER = 'https://op.example.com'
const adapter = await memoryAdapter()
const document = metadata(resolveConfig({ issuer: ISSUER, adapter, interactionUrl: `${ISSUER}/interaction` }), ['RS256'])

describe('the discovery document this OP writes is one @oidcraft/core can read', () => {
  // A compile-time assertion first: `satisfies` checks every member they share is the same type.
  test('every endpoint the relying-party core reads is one this OP emits', () => {
    const read = document satisfies OpenIdConfiguration

    const required: Required<
      Pick<
        OpenIdConfiguration,
        | 'issuer'
        | 'authorization_endpoint'
        | 'token_endpoint'
        | 'userinfo_endpoint'
        | 'jwks_uri'
        | 'end_session_endpoint'
        | 'scopes_supported'
        | 'code_challenge_methods_supported'
        | 'authorization_response_iss_parameter_supported'
      >
    > = read

    expect(required.issuer).toBe(ISSUER)
  })

  // The round trip, rather than a second list of field names: what a client ends up configured with
  // after reading this OP's document is the thing that actually has to be right.
  test('a client configured from it comes out with every endpoint filled in', () => {
    const configured = applyDiscovery({ issuerPath: ISSUER, clientId: 'demo' }, document)

    expect(configured.authorizePath).toBe(`${ISSUER}/authorize`)
    expect(configured.tokenPath).toBe(`${ISSUER}/token`)
    expect(configured.userPath).toBe(`${ISSUER}/userinfo`)
    expect(configured.jwksUri).toBe(`${ISSUER}/jwks`)
    expect(configured.logoutPath).toBe(`${ISSUER}/session/end`)
    // FR-C3 on this side is `pkce: true` on the other: the client turns PKCE on because the document
    // says S256 is supported, which is the only reason those two facts stay in step.
    expect(configured.pkce).toBe(true)
    // FR-C14, and what makes the mix-up check in `completeAuthorization` mandatory against this OP.
    expect(configured.issuerParameter).toBe(true)
  })

  test('and the issuer it asserts is the one it was fetched from, so the document validates', () => {
    expect(() => applyDiscovery({ issuerPath: ISSUER }, document)).not.toThrow()
    expect(() => applyDiscovery({ issuerPath: 'https://someone.else' }, document)).toThrow(/not the provider you think it is/)
  })
})
