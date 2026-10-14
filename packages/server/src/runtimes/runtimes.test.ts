import { describe, expect, test } from 'bun:test'
import { certificateThumbprint } from '../binding/mtls'
import type { RequestContext } from '../context'
import { bunContext } from './bun'
import { denoContext } from './deno'
import { workerdContext } from './workerd'

/**
 * These providers exist because nothing in `RequestContext` is carried by `Request` on any runtime
 * (FR-R4). Each is tiny, so the risk is not complexity but silence: a provider that returns nothing
 * looks fine until an audit log has no addresses in it.
 */
const request = (headers: Record<string, string> = {}) => new Request('https://op.example.com/token', { method: 'POST', headers })

const DER = new Uint8Array([0x30, 0x82, 0x01, 0x0a, 0x02, 0x01, 0x05])
const hex = (bytes: ArrayBuffer) => Array.from(new Uint8Array(bytes), byte => byte.toString(16).padStart(2, '0')).join('')
const fingerprint = hex(await crypto.subtle.digest('SHA-256', DER))
const presented = { certPresented: '1', certVerified: 'SUCCESS', certFingerprintSHA256: fingerprint }

describe('bun', () => {
  test('takes the peer address from the server, since Request has none', () => {
    const context = bunContext('https://op.example.com', { requestIP: () => ({ address: '203.0.113.7' }) })(request())
    expect(context).toEqual({ issuer: 'https://op.example.com', clientIp: '203.0.113.7' })
  })

  test('a connection with no address is simply absent, not a crash', () => {
    expect(bunContext('https://op.example.com', { requestIP: () => null })(request())).toEqual({
      issuer: 'https://op.example.com',
      clientIp: undefined
    })
  })

  // G-8: Bun.serve exposes no peer certificate, so mTLS client auth cannot work there.
  test('never produces a client certificate', () => {
    const context: RequestContext = bunContext('https://op.example.com', { requestIP: () => ({ address: '::1' }) })(request())
    expect(context.clientCertificate).toBeUndefined()
  })
})

describe('deno', () => {
  test('takes the peer address from the handler info argument', () => {
    const context = denoContext('https://op.example.com')(request(), { remoteAddr: { hostname: '198.51.100.4' } })
    expect(context.clientIp).toBe('198.51.100.4')
  })

  test('tolerates info without a hostname', () => {
    expect(denoContext('https://op.example.com')(request(), { remoteAddr: {} }).clientIp).toBeUndefined()
  })
})

describe('workerd', () => {
  test('takes the peer address from CF-Connecting-IP', () => {
    const context = workerdContext('https://op.example.com')(request({ 'cf-connecting-ip': '192.0.2.9' }))
    expect(context.clientIp).toBe('192.0.2.9')
  })

  // Only "SUCCESS" means the edge verified it; anything else is an unverified claim by the client.
  test('accepts a client certificate only when the edge verified it', () => {
    const verified = workerdContext('https://op.example.com')(request(), {
      tlsClientAuth: { ...presented, certSubjectDN: 'CN=rp', certIssuerDN: 'CN=ca' }
    })
    expect(verified.clientCertificate?.subjectDn).toBe('CN=rp')

    for (const auth of [
      { certPresented: '1', certVerified: 'FAILED' },
      { certPresented: '0', certVerified: 'SUCCESS' },
      { certPresented: '1' },
      {}
    ]) {
      const context = workerdContext('https://op.example.com')(request(), { tlsClientAuth: auth })
      expect({ auth, cert: context.clientCertificate }).toEqual({ auth, cert: undefined })
    }
  })

  // FR-C13: Workers never see the DER, so the thumbprint comes from Cloudflare's fingerprint of it.
  test('derives the RFC 8705 thumbprint from the edge fingerprint', async () => {
    const context = workerdContext('https://op.example.com')(request(), { tlsClientAuth: presented })
    expect(context.clientCertificate?.thumbprint).toBe(await certificateThumbprint(DER))

    const other = workerdContext('https://op.example.com')(request(), {
      tlsClientAuth: { ...presented, certFingerprintSHA256: 'ab'.repeat(32) }
    })
    expect(other.clientCertificate?.thumbprint).not.toBe(context.clientCertificate?.thumbprint)
  })

  test('a verified certificate without a usable fingerprint is no certificate', () => {
    const { certFingerprintSHA256: _, ...withoutFingerprint } = presented
    for (const tlsClientAuth of [
      withoutFingerprint,
      ...['', 'not-hex', 'ab'.repeat(20)].map(certFingerprintSHA256 => ({ ...presented, certFingerprintSHA256 }))
    ]) {
      expect(workerdContext('https://op.example.com')(request(), { tlsClientAuth }).clientCertificate).toBeUndefined()
    }
  })

  test('no cf object at all is handled', () => {
    expect(workerdContext('https://op.example.com')(request()).clientCertificate).toBeUndefined()
  })
})

describe('every runtime', () => {
  // NFR-S6: the issuer is configuration, and a provider that let a header influence it would be
  // the one place that could forge it.
  test('reports the configured issuer whatever the request claims', () => {
    const hostile = request({ host: 'evil.example.net', 'x-forwarded-host': 'evil.example.net' })
    expect(bunContext('https://op.example.com', { requestIP: () => null })(hostile).issuer).toBe('https://op.example.com')
    expect(denoContext('https://op.example.com')(hostile, { remoteAddr: {} }).issuer).toBe('https://op.example.com')
    expect(workerdContext('https://op.example.com')(hostile).issuer).toBe('https://op.example.com')
  })
})

// FR-I7: both write PHC argon2id strings, so a deployment can move between Bun and Node without
// resetting every password.
describe('password hashers', () => {
  test('each verifies its own hash and the other’s, and refuses a wrong password', async () => {
    const { bunPasswordHasher } = await import('./bun')
    const { nodePasswordHasher } = await import('./node')
    const fromBun = await bunPasswordHasher.hash('correct horse')
    const fromNode = await nodePasswordHasher.hash('correct horse')
    expect(fromNode).toStartWith('$argon2id$v=19$')
    expect(await nodePasswordHasher.verify('correct horse', fromBun)).toBe(true)
    expect(await bunPasswordHasher.verify('correct horse', fromNode)).toBe(true)
    expect(await nodePasswordHasher.verify('wrong horse', fromNode)).toBe(false)
    expect(await nodePasswordHasher.verify('correct horse', 'not a hash')).toBe(false)
  })
})
