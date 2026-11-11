import { afterAll, describe, expect, test } from 'bun:test'
import { X509Certificate } from 'node:crypto'
import { createServer } from 'node:http'
import { memoryAdapter } from '@oidcraft/adapter/memory'
import { certificateThumbprint } from '../../binding/mtls'
import { createProvider } from '../../provider'
import { nodeContext, toNodeHandler } from './index'
import { CA_SIGNED, SELF_SIGNED } from './test-certificates'

const adapter = await memoryAdapter()
const provider = createProvider({ interactionUrl: 'https://op.example.com/interaction', issuer: 'http://127.0.0.1:0', adapter })

/** The bridge only proves anything against a real node:http server (FR-R3). */
const server = createServer(toNodeHandler(provider.handle, 'http://127.0.0.1'))
await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
const { port } = server.address() as { port: number }
const base = `http://127.0.0.1:${port}`

afterAll(() => server.close())

describe('node bridge', () => {
  test('serves discovery through node:http', async () => {
    const response = await fetch(`${base}/.well-known/openid-configuration`)
    expect(response.status).toBe(200)
    expect((await response.json()).issuer).toBe('http://127.0.0.1:0')
  })

  test('serves jwks and preserves response headers', async () => {
    const response = await fetch(`${base}/jwks`)
    expect(response.status).toBe(200)
    expect(response.headers.get('cache-control')).toContain('max-age')
    expect((await response.json()).keys).toHaveLength(2)
  })

  test('carries a POST body through to the handler', async () => {
    const response = await fetch(`${base}/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'grant_type=authorization_code&client_id=ghost'
    })
    expect(response.status).toBe(401)
    expect((await response.json()).error).toBe('invalid_client')
  })

  test('preserves the status and the OAuth error shape', async () => {
    const response = await fetch(`${base}/nope`)
    expect(response.status).toBe(404)
    expect((await response.json()).error).toBe('invalid_request')
  })

  test('preserves a 405 and its Allow header', async () => {
    const response = await fetch(`${base}/jwks`, { method: 'POST' })
    expect(response.status).toBe(405)
    expect(response.headers.get('allow')).toBe('GET')
  })
})

describe('nodeContext', () => {
  const incoming = (forwardedFor?: string) =>
    ({ headers: forwardedFor ? { 'x-forwarded-for': forwardedFor } : {}, socket: { remoteAddress: '10.0.0.2' } }) as never

  // NFR-S6: everything left of the proxy's own entry was written by the client.
  test('with trustProxy, takes the address the proxy appended, not one the client wrote', () => {
    const context = nodeContext('https://op.example.com', { trustProxy: true })(incoming('6.6.6.6, 203.0.113.9'))
    expect(context.clientIp).toBe('203.0.113.9')
  })

  test('without trustProxy, the header is ignored', () => {
    expect(nodeContext('https://op.example.com')(incoming('6.6.6.6')).clientIp).toBe('10.0.0.2')
  })

  // Bun's node:tls hands over no client certificate (G-8), so a real handshake cannot run here; the
  // socket is a stand-in carrying the DER a TLS socket would. Checked over real TLS on Node 26.
  const presenting = (pem: string, authorized: boolean) =>
    ({
      headers: {},
      socket: { remoteAddress: '10.0.0.2', authorized, getPeerCertificate: () => ({ raw: new X509Certificate(pem).raw }) }
    }) as never

  test('a CA-verified certificate arrives verified, with its subject as an RFC 4514 name', async () => {
    const certificate = nodeContext('https://op.example.com')(presenting(CA_SIGNED, true)).clientCertificate
    expect(certificate).toEqual({
      thumbprint: await certificateThumbprint(new X509Certificate(CA_SIGNED).raw),
      verified: true,
      subjectDn: 'CN=rp,O=Acme\\, Inc.,C=US',
      issuerDn: 'CN=Test CA'
    })
  })

  // RFC 8705 §2.2: the listener cannot verify a self-signed certificate, and need not — the handshake proved its key.
  test('a certificate the listener did not verify still arrives, marked unverified', () => {
    const certificate = nodeContext('https://op.example.com')(presenting(SELF_SIGNED, false)).clientCertificate
    expect(certificate).toMatchObject({ verified: false, subjectDn: 'CN=self' })
  })

  test('no certificate presented is none', () => {
    const plain = { headers: {}, socket: { authorized: false, getPeerCertificate: () => ({}) } } as never
    expect(nodeContext('https://op.example.com')(plain).clientCertificate).toBeUndefined()
  })
})
