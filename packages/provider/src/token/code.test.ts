import { describe, expect, setSystemTime, test } from 'bun:test'
import { decodeJwt } from 'jose'
import { withHashedArtifacts } from '../artifacts'
import type { Provider } from '../provider'
import { adapter, basic, build, client, endSession, ISSUER, tokensFor, useFlow } from '../test-flow'

const EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange'

useFlow()

describe('refresh token lifetime', () => {
  const refresh = (provider: Provider, token: string) =>
    provider.handle(
      new Request(`${ISSUER}/token`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: basic() },
        body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: token }).toString()
      })
    )

  // Rotation restarts the idle lifetime; without an absolute one a family would live forever.
  test('a family ends at its absolute lifetime however often it rotates', async () => {
    await adapter.clients.upsert?.(client({ scopes: ['openid', 'offline_access'] }))
    const provider = build({ ttl: { refreshToken: 3600, refreshTokenFamily: 7200 } })
    const start = Date.now()
    let token = (await tokensFor(provider, 'rp', undefined, { scope: 'openid offline_access' })).refresh_token as string
    try {
      for (const minutes of [50, 100]) {
        setSystemTime(new Date(start + minutes * 60_000))
        token = (await (await refresh(provider, token)).json()).refresh_token
        expect(token).toBeTruthy()
      }
      setSystemTime(new Date(start + 130 * 60_000))
      expect((await (await refresh(provider, token)).json()).error).toBe('invalid_grant')
    } finally {
      setSystemTime()
    }
  })

  // OIDC Core §11: offline access is for when the user is not there.
  test('offline access outlives the browser session, but not the grant', async () => {
    await adapter.clients.upsert?.(client({ scopes: ['openid', 'offline_access'] }))
    const provider = build()
    const issued = await tokensFor(provider, 'rp', undefined, { scope: 'openid offline_access' })
    const session = (await adapter.sessions.listForAccount('ada'))[0]
    await adapter.sessions.destroy(session?.id as string)

    const refreshed = await (await refresh(provider, issued.refresh_token)).json()
    expect(refreshed.access_token).toBeTruthy()
    expect(decodeJwt(refreshed.id_token).auth_time).toBe(decodeJwt(issued.id_token).auth_time as number)
    expect(await adapter.sessions.find(session?.id as string)).toBeUndefined()

    const grant = await adapter.grants.findByAccountAndClient('ada', 'rp')
    await adapter.grants.destroy(grant?.id as string)
    expect((await (await refresh(provider, refreshed.refresh_token)).json()).error).toBe('invalid_grant')
  })
})

describe('FR-T6: a refresh token without offline_access is bound to the session', () => {
  const refresh = (provider: Provider, token: string) =>
    provider.handle(
      new Request(`${ISSUER}/token`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: basic() },
        body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: token }).toString()
      })
    )

  test('it is issued, rotates, and dies when the session ends', async () => {
    await adapter.clients.upsert?.(client())
    const provider = build()
    const issued = await tokensFor(provider, 'rp')
    expect(issued.refresh_token).toBeTruthy()

    const rotated = await (await refresh(provider, issued.refresh_token)).json()
    expect(rotated.refresh_token).toBeTruthy()
    expect(rotated.refresh_token).not.toBe(issued.refresh_token)

    const session = (await adapter.sessions.listForAccount('ada'))[0]
    await adapter.sessions.destroy(session?.id as string)
    expect((await (await refresh(provider, rotated.refresh_token)).json()).error).toBe('invalid_grant')
  })

  // FR-T7: ended means ended everywhere it can be presented, not only at the refresh grant.
  test('after logout it introspects inactive and is no subject to exchange', async () => {
    await adapter.clients.upsert?.(client({ grantTypes: ['authorization_code', 'refresh_token', EXCHANGE] }))
    const provider = build({ exchangePolicy: () => ({ accountId: 'ada', scopes: ['openid'] }) })
    const issued = await tokensFor(provider, 'rp')
    const post = (body: Record<string, string>, path = '/token') =>
      provider.handle(
        new Request(`${ISSUER}${path}`, {
          method: 'POST',
          headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: basic() },
          body: new URLSearchParams(body).toString()
        })
      )
    const introspect = async () => (await (await post({ token: issued.refresh_token }, '/introspect')).json()).active
    const exchange = () =>
      post({
        grant_type: EXCHANGE,
        subject_token: issued.refresh_token,
        subject_token_type: 'urn:ietf:params:oauth:token-type:refresh_token'
      })

    expect(await introspect()).toBe(true)
    expect((await exchange()).status).toBe(200)
    await endSession(provider, issued.secret, issued.id_token)
    expect(await introspect()).toBe(false)
    expect((await (await exchange()).json()).error).toBe('invalid_request')
  })

  test('it expires no later than the session, however long its own lifetime', async () => {
    await adapter.clients.upsert?.(client())
    const issued = await tokensFor(build({ ttl: { session: 600, refreshToken: 86_400 } }), 'rp')
    const stored = await withHashedArtifacts(adapter).artifacts.find('refresh_token', issued.refresh_token)
    const session = (await adapter.sessions.listForAccount('ada'))[0]
    expect(stored?.expiresAt.getTime()).toBeLessThanOrEqual(session?.expiresAt.getTime() as number)
  })

  test('a client not registered for the refresh_token grant gets none', async () => {
    await adapter.clients.upsert?.(client({ grantTypes: ['authorization_code'] }))
    const issued = await tokensFor(build(), 'rp')
    expect(issued.refresh_token).toBeUndefined()
  })
})
