import { describe, expect, it } from 'bun:test'
import {
  base64url,
  base64urlDecode,
  calculatePKCECodeChallenge,
  constantTimeEquals,
  randomNonce,
  randomPKCECodeVerifier,
  randomState,
  randomString
} from './random'

const BASE64URL = /^[A-Za-z0-9\-_]+$/

describe('random', () => {
  it('produces the requested length from the base64url alphabet', () => {
    const value = randomString(48)

    expect(value).toHaveLength(48)
    expect(value).toMatch(BASE64URL)
  })

  it('does not repeat itself', () => {
    const values = new Set(Array.from({ length: 1000 }, () => randomString()))

    expect(values.size).toBe(1000)
  })

  it('carries at least 256 bits by default, which every server token relies on (NFR-S3)', () => {
    expect(randomString().length * 6).toBeGreaterThanOrEqual(256)
  })

  it('decodes what it encodes, at every padding length', () => {
    for (let length = 0; length < 8; length++) {
      const bytes = crypto.getRandomValues(new Uint8Array(length))
      expect(base64urlDecode(base64url(bytes))).toEqual(bytes)
    }
  })

  it('decodes the url-safe alphabet, which atob alone refuses', () => {
    expect(base64urlDecode('-_8')).toEqual(new Uint8Array([0xfb, 0xff]))
  })

  it('compares secrets by value, whatever their lengths', async () => {
    expect(await constantTimeEquals('secret', 'secret')).toBe(true)
    expect(await constantTimeEquals('secret', 'secreT')).toBe(false)
    expect(await constantTimeEquals('secret', 'secret-longer')).toBe(false)
    expect(await constantTimeEquals('', '')).toBe(true)
  })

  it('gives state, nonce and verifier the same shape', () => {
    for (const value of [randomState(), randomNonce(), randomPKCECodeVerifier()]) {
      // RFC 7636 §4.1 puts the verifier between 43 and 128 unreserved characters
      expect(value.length).toBeGreaterThanOrEqual(43)
      expect(value.length).toBeLessThanOrEqual(128)
      expect(value).toMatch(BASE64URL)
    }
  })

  it('challenges the verifier as unpadded base64url, and stably', async () => {
    const verifier = randomPKCECodeVerifier()
    const challenge = await calculatePKCECodeChallenge(verifier)

    expect(challenge).toMatch(BASE64URL)
    expect(challenge).not.toContain('=')
    expect(await calculatePKCECodeChallenge(verifier)).toBe(challenge)
  })

  it('challenges different verifiers differently', async () => {
    expect(await calculatePKCECodeChallenge('one')).not.toBe(await calculatePKCECodeChallenge('two'))
  })
})
