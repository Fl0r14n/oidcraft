import { describe, expect, test } from 'bun:test'
import { ConfigurationError } from './errors'
import { generateKey, staticKeyStore } from './keys'

const es256 = await generateKey('ES256')
const rs256 = await generateKey('RS256')

describe('key stores', () => {
  test('a generated key carries a thumbprint kid and its algorithm', () => {
    expect(es256.kid).toBeTruthy()
    expect(es256.alg).toBe('ES256')
  })

  test('a keystore with no keys is a configuration error, not a runtime surprise', () => {
    expect(() => staticKeyStore([])).toThrow(ConfigurationError)
  })

  // FR-T1, OIDC Core §15.1: RS256 is the one algorithm every OP must sign with.
  test('a key set without RS256 is a configuration error', () => {
    expect(() => staticKeyStore([es256])).toThrow(ConfigurationError)
    expect(staticKeyStore([es256, rs256])).toBeTruthy()
  })

  test('a key without an alg is rejected', () => {
    expect(() => staticKeyStore([{ ...es256, alg: '' }, rs256])).toThrow(ConfigurationError)
  })
})
