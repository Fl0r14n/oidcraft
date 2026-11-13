import { describe, expect, test } from 'bun:test'
import type { Client } from '../index'
import { adapter, authorizeUrl, basic, client, go, loginAndConsent, post, REDIRECT, useFlow, verifier } from '../test-flow'

useFlow()

describe('PKCE exemption (FR-C3)', () => {
  const withoutPkce = (over: Partial<Client> = {}) =>
    adapter.clients.upsert?.(client({ clientId: 'rp-nonce', requirePkce: false, ...over }))
  const noChallenge = { client_id: 'rp-nonce', code_challenge: '', code_challenge_method: '' }
  const exchange = (code: string, over: Record<string, string> = {}) =>
    post('/token', { grant_type: 'authorization_code', code, redirect_uri: REDIRECT, ...over }, { authorization: basic('rp-nonce') })
  const errorOf = async (over: Record<string, string>) =>
    new URL((await go(authorizeUrl(over))).headers.get('location') as string).searchParams.get('error')

  test('an opted-out confidential client with a nonce completes the flow without PKCE', async () => {
    await withoutPkce()
    const { location } = await loginAndConsent(noChallenge)
    const response = await exchange(location.searchParams.get('code') as string)
    expect(response.status).toBe(200)
    expect((await response.json()).id_token).toBeTruthy()
  })

  test('an opted-out client without a nonce is refused', async () => {
    await withoutPkce()
    expect(await errorOf({ ...noChallenge, nonce: '' })).toBe('invalid_request')
  })

  test('a public client cannot be exempted, even with a nonce', async () => {
    await withoutPkce({ tokenEndpointAuthMethod: 'none' })
    expect(await errorOf(noChallenge)).toBe('invalid_request')
  })

  // RFC 9700 §4.8.2: the downgrade is a verifier arriving for a code that was issued without a challenge.
  test('a code_verifier for a code issued without a challenge is refused', async () => {
    await withoutPkce()
    const { location } = await loginAndConsent(noChallenge)
    const response = await exchange(location.searchParams.get('code') as string, { code_verifier: verifier })
    expect(response.status).toBe(400)
    expect((await response.json()).error).toBe('invalid_grant')
  })

  test('a challenge an opted-out client did send is still enforced', async () => {
    await withoutPkce()
    const { location } = await loginAndConsent({ client_id: 'rp-nonce' })
    const response = await exchange(location.searchParams.get('code') as string)
    expect(response.status).toBe(400)
    expect((await response.json()).error).toBe('invalid_grant')
  })
})
