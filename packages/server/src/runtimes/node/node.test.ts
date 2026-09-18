import { afterAll, describe, expect, test } from 'bun:test'
import { createServer } from 'node:http'
import { memoryAdapter } from '../../adapters/memory'
import { createProvider } from '../../provider'
import { toNodeHandler } from './index'

const adapter = await memoryAdapter()
const provider = createProvider({ issuer: 'http://127.0.0.1:0', adapter })

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
    expect((await response.json()).keys).toHaveLength(1)
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
