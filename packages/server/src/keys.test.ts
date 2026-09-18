import { describe, expect, test } from 'bun:test'
import { ConfigurationError } from './errors'
import { generateKey, jwksResponseBody, publicJwk, signingAlgorithms, signingKey, staticKeyStore } from './keys'

const es256 = await generateKey('ES256')
const rs256 = await generateKey('RS256')

describe('keys', () => {
  test('a generated key carries a thumbprint kid and its algorithm', () => {
    expect(es256.kid).toBeTruthy()
    expect(es256.alg).toBe('ES256')
  })

  // The whole point of a JWKS: it must never carry the private half.
  test('the public jwk drops every private member', () => {
    const jwk = publicJwk(es256.privateJwk as never)
    expect(jwk).not.toHaveProperty('d')
    expect(jwk).toHaveProperty('x')
    expect(jwk).toHaveProperty('kid')
  })

  test('the jwks response exposes no private key material', () => {
    const body = JSON.stringify(jwksResponseBody([es256, rs256]))
    expect(body).not.toContain('"d"')
    expect(body).not.toContain('"p"')
    expect(body).not.toContain('"q"')
    expect(JSON.parse(body).keys).toHaveLength(2)
  })

  // FR-C10 / NFR-S7: prepending a key rotates signing without invalidating tokens the old one signed.
  test('the first key of an algorithm signs and the rest only verify', async () => {
    const replacement = await generateKey('ES256')
    const rotated = [replacement, es256, rs256]
    expect(signingKey(rotated, 'ES256')?.kid).toBe(replacement.kid)
    expect(jwksResponseBody(rotated).keys).toHaveLength(3)
  })

  test('advertised algorithms come from the keys that exist', () => {
    expect(signingAlgorithms([es256, rs256]).sort()).toEqual(['ES256', 'RS256'])
  })

  test('a keystore with no keys is a configuration error, not a runtime surprise', () => {
    expect(() => staticKeyStore([])).toThrow(ConfigurationError)
  })

  test('a key without an alg is rejected', () => {
    expect(() => staticKeyStore([{ ...es256, alg: '' }])).toThrow(ConfigurationError)
  })
})
