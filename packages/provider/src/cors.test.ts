import { describe, expect, test } from 'bun:test'
import type { Provider } from './provider'
import { adapter, basic, build, client, ISSUER, REDIRECT, tokensFor, useFlow } from './test-flow'

useFlow()

describe('CORS', () => {
  const RP = 'https://rp.example.com'
  const token = (provider: Provider, origin: string, authorization = basic()) =>
    provider.handle(
      new Request(`${ISSUER}/token`, {
        method: 'POST',
        headers: { origin, authorization, 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'authorization_code', code: 'x', redirect_uri: REDIRECT }).toString()
      })
    )

  test('discovery and the key set are readable from any origin', async () => {
    const provider = build()
    for (const path of ['/.well-known/openid-configuration', '/jwks']) {
      const response = await provider.handle(new Request(`${ISSUER}${path}`, { headers: { origin: 'https://anywhere.example' } }))
      expect(response.headers.get('access-control-allow-origin')).toBe('*')
    }
  })

  test('a preflight on a client endpoint names the methods and the headers a browser client sends', async () => {
    const response = await build().handle(
      new Request(`${ISSUER}/token`, { method: 'OPTIONS', headers: { origin: RP, 'access-control-request-method': 'POST' } })
    )
    expect(response.status).toBe(204)
    expect(response.headers.get('access-control-allow-origin')).toBe(RP)
    expect(response.headers.get('access-control-allow-headers')).toContain('dpop')
  })

  // The registration already says where the client lives; nothing else is configured.
  test("a response is readable only on the origin of the calling client's redirect URIs", async () => {
    await adapter.clients.upsert?.(client())
    const provider = build()
    const mine = await token(provider, RP)
    expect(mine.status).toBe(400)
    expect(mine.headers.get('access-control-allow-origin')).toBe(RP)
    expect(mine.headers.get('access-control-expose-headers')).toContain('dpop-nonce')

    const theirs = await token(provider, 'https://evil.example')
    expect(theirs.headers.get('access-control-allow-origin')).toBeNull()
    expect(theirs.headers.get('vary')).toContain('origin')
  })

  test('the client the handler authenticated decides, without a second lookup', async () => {
    await adapter.clients.upsert?.(client())
    let lookups = 0
    const counted = {
      ...adapter,
      clients: {
        ...adapter.clients,
        find: (clientId: string) => {
          lookups++
          return adapter.clients.find(clientId)
        }
      }
    }
    const response = await token(build({ adapter: counted }), RP)
    expect(response.headers.get('access-control-allow-origin')).toBe(RP)
    expect(lookups).toBe(1)
  })

  test('UserInfo identifies the client by its access token', async () => {
    await adapter.clients.upsert?.(client())
    const provider = build()
    const issued = await tokensFor(provider)
    const response = await provider.handle(
      new Request(`${ISSUER}/userinfo`, { headers: { origin: RP, authorization: `Bearer ${issued.access_token}` } })
    )
    expect(response.status).toBe(200)
    expect(response.headers.get('access-control-allow-origin')).toBe(RP)
  })
})
