import { describe, expect, test } from 'bun:test'
import { withHashedArtifacts } from '../artifacts'
import type { Provider } from '../provider'
import { adapter, basic, build, client, ISSUER, tokensFor, useFlow } from '../test-flow'

useFlow()

describe('FR-C8: introspection by a resource server', () => {
  const introspect = async (provider: Provider, token: string, as: string) =>
    (
      await provider.handle(
        new Request(`${ISSUER}/introspect`, {
          method: 'POST',
          headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: basic(as) },
          body: new URLSearchParams({ token }).toString()
        })
      )
    ).json()

  test('a resource server may introspect access tokens issued to other clients; another client may not', async () => {
    await adapter.clients.upsert?.(client({ scopes: ['openid', 'profile', 'offline_access'] }))
    await adapter.clients.upsert?.(client({ clientId: 'api', resourceServer: true }))
    await adapter.clients.upsert?.(client({ clientId: 'other' }))
    const provider = build()
    const issued = await tokensFor(provider, 'rp', undefined, { scope: 'openid offline_access' })

    expect(await introspect(provider, issued.access_token, 'api')).toMatchObject({ active: true, client_id: 'rp', sub: 'ada' })
    expect(await introspect(provider, issued.access_token, 'other')).toEqual({ active: false })
    // A refresh token is never presented to a resource server.
    expect(await introspect(provider, issued.refresh_token, 'api')).toEqual({ active: false })
  })

  test('a token restricted to another audience is inactive to this resource server', async () => {
    await adapter.clients.upsert?.(client())
    await adapter.clients.upsert?.(client({ clientId: 'api', resourceServer: true }))
    const provider = build()
    const issued = await tokensFor(provider)
    const stored = await withHashedArtifacts(adapter).artifacts.find('access_token', issued.access_token)
    await withHashedArtifacts(adapter).artifacts.upsert({
      ...(stored as NonNullable<typeof stored>),
      payload: { ...stored?.payload, aud: 'billing' }
    })
    expect(await introspect(provider, issued.access_token, 'api')).toEqual({ active: false })
  })

  test('iat is when the token was issued, not when it expires', async () => {
    await adapter.clients.upsert?.(client())
    const provider = build()
    const before = Math.floor(Date.now() / 1000)
    const issued = await tokensFor(provider)
    const body = await introspect(provider, issued.access_token, 'rp')
    expect(body.iat).toBeGreaterThanOrEqual(before)
    expect(body.iat).toBeLessThan(body.exp)
  })
})
