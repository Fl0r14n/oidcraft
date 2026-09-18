import { describe, expect, it } from 'bun:test'
import { authorizationUrl } from './authorization'
import { defaultOAuthFunctions } from './functions'
import { createIdTokenVerifier } from './jwt'
import { assertSecure, InsecureEndpointError, isTenantTemplate, sameIssuer } from './secure'

describe('assertSecure', () => {
  it('passes https through unchanged', () => {
    expect(assertSecure('https://auth.com/token')).toBe('https://auth.com/token')
  })

  it('refuses http, because a code on the wire in clear is already someone else’s', () => {
    expect(() => assertSecure('http://auth.com/token')).toThrow(InsecureEndpointError)
  })

  it('refuses http on localhost too — allowInsecure is the one way to say it', () => {
    expect(() => assertSecure('http://localhost:3000/token')).toThrow(InsecureEndpointError)
    expect(assertSecure('http://localhost:3000/token', true)).toBe('http://localhost:3000/token')
  })

  it('leaves a relative path alone: it inherits an origin this library does not choose', () => {
    expect(assertSecure('/oauth/token')).toBe('/oauth/token')
    expect(assertSecure(undefined)).toBeUndefined()
  })

  it('names the url it refused, so the message says which endpoint to fix', () => {
    try {
      assertSecure('http://auth.com/token')
      expect.unreachable()
    } catch (error) {
      expect((error as InsecureEndpointError).url).toBe('http://auth.com/token')
    }
  })
})

describe('the guard reaches every endpoint a secret or a code crosses', () => {
  const insecure = { clientId: 'c', clientSecret: 's', issuerPath: 'http://auth.com', allowInsecure: false } as any

  it('refuses to send the browser to an http authorization endpoint', () => {
    expect(
      authorizationUrl({ redirectUri: 'https://app.com/cb', responseType: 'code' }, { authorizePath: 'http://auth.com/a' } as any)
    ).rejects.toThrow(InsecureEndpointError)
  })

  it('refuses an http token endpoint', () => {
    expect(defaultOAuthFunctions.authorize({ code: 'x' }, { ...insecure, tokenPath: 'http://auth.com/t' })).rejects.toThrow(
      InsecureEndpointError
    )
  })

  it('refuses an http discovery document', () => {
    expect(defaultOAuthFunctions.openIdConfiguration(insecure)).rejects.toThrow(InsecureEndpointError)
  })

  it('refuses an http userinfo endpoint', () => {
    expect(defaultOAuthFunctions.userInfo({ ...insecure, userPath: 'http://auth.com/u' })).rejects.toThrow(InsecureEndpointError)
  })

  // Keys fetched over http are keys an attacker on the path picked, which makes the signature check
  // below them decorative.
  it('refuses an http jwks uri', () => {
    expect(() => createIdTokenVerifier({ jwksUri: 'http://auth.com/jwks' })).toThrow(InsecureEndpointError)
  })

  it('throws rather than returning undefined, so a misconfiguration is not reported as an outage', () => {
    expect(defaultOAuthFunctions.refresh({ refresh_token: 'r' }, { ...insecure, tokenPath: 'http://auth.com/t' })).rejects.toThrow(
      InsecureEndpointError
    )
  })
})

describe('sameIssuer', () => {
  it('ignores a trailing slash and nothing else', () => {
    expect(sameIssuer('https://auth.com/', 'https://auth.com')).toBe(true)
    expect(sameIssuer('https://auth.com', 'https://auth.com/realms/x')).toBe(false)
    expect(sameIssuer('https://auth.com', 'http://auth.com')).toBe(false)
  })
})

describe('isTenantTemplate', () => {
  it('recognises the one issuer that can never match literally', () => {
    expect(isTenantTemplate('https://login.microsoftonline.com/{tenantid}/v2.0')).toBe(true)
    expect(isTenantTemplate('https://auth.com')).toBe(false)
    expect(isTenantTemplate(undefined)).toBe(false)
  })
})
