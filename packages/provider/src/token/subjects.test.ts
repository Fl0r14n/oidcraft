import { describe, expect, test } from 'bun:test'
import { decodeJwt } from 'jose'
import type { Provider } from '../provider'
import { adapter, basic, build, client, endSession, ISSUER, tokensFor, useFlow } from '../test-flow'

useFlow()

describe('FR-C18: a pairwise subject never leaks the account id', () => {
  const pairwise = (over: Record<string, unknown> = {}) => build({ subjectType: 'pairwise', pairwiseSalt: 'a-long-enough-salt', ...over })
  const post = (provider: Provider, path: string, body: Record<string, string>) =>
    provider.handle(
      new Request(`${ISSUER}${path}`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: basic() },
        body: new URLSearchParams(body).toString()
      })
    )

  test('UserInfo and introspection report the sub the ID token carried', async () => {
    await adapter.clients.upsert?.(client())
    adapter.accounts.claims = async () => ({ sub: 'ada', name: 'Ada' })
    const provider = pairwise()
    const issued = await tokensFor(provider)
    const sub = decodeJwt(issued.id_token).sub
    expect(sub).not.toBe('ada')

    const userinfo = await (
      await provider.handle(new Request(`${ISSUER}/userinfo`, { headers: { authorization: `Bearer ${issued.access_token}` } }))
    ).json()
    expect(userinfo.sub).toBe(sub)
    expect((await (await post(provider, '/introspect', { token: issued.access_token })).json()).sub).toBe(sub)
  })

  test('the back-channel logout token carries the pairwise sub', async () => {
    await adapter.clients.upsert?.(client({ backchannelLogoutUri: 'https://rp.example.com/logout' }))
    let tokens: { logoutToken: string }[] = []
    const provider = pairwise({
      onLogout: (received: { logoutToken: string }[]) => {
        tokens = received
      }
    })
    const issued = await tokensFor(provider)
    await endSession(provider, issued.secret, issued.id_token)
    expect(decodeJwt(tokens[0]?.logoutToken as string).sub).toBe(decodeJwt(issued.id_token).sub as string)
  })
})
