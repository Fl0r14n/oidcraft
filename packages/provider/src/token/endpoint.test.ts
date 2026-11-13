import { describe, expect, test } from 'bun:test'
import { randomString, sha256 } from '@oidcraft/core'
import { base64url, createLocalJWKSet, decodeProtectedHeader, jwtVerify } from 'jose'
import type { Client } from '../index'
import { createProvider } from '../provider'
import { adapter, authorizeUrl, basic, drive, go, ISSUER, loginAndConsent, post, provider, REDIRECT, useFlow, verifier } from '../test-flow'

useFlow()

describe('token endpoint', () => {
  const exchange = async (code: string, over: Record<string, string> = {}) =>
    post(
      '/token',
      { grant_type: 'authorization_code', code, redirect_uri: REDIRECT, code_verifier: verifier, ...over },
      {
        authorization: basic()
      }
    )

  test('exchanges a code for access, refresh and ID tokens', async () => {
    const { location } = await loginAndConsent()
    const response = await exchange(location.searchParams.get('code') as string)
    expect(response.status).toBe(200)
    const body = await response.json()
    expect(body.token_type).toBe('Bearer')
    expect(body.access_token).toBeTruthy()
    expect(body.refresh_token).toBeTruthy()
    expect(body.id_token).toBeTruthy()
    expect(response.headers.get('cache-control')).toBe('no-store')
  })

  test('the ID token verifies against the published JWKS and carries the nonce', async () => {
    const { location } = await loginAndConsent()
    const body = await (await exchange(location.searchParams.get('code') as string)).json()
    const jwks = await (await provider.handle(new Request(`${ISSUER}/jwks`))).json()
    const { payload } = await jwtVerify(body.id_token, createLocalJWKSet(jwks), { issuer: ISSUER, audience: 'rp' })
    expect(payload.sub).toBe('ada')
    expect(payload.nonce).toBe('n-0S6_WzA2Mj')
    expect(payload.at_hash).toBeTruthy()
    // OIDC Core §5.4: an access token was issued, so profile claims are UserInfo's to release.
    expect(payload).not.toHaveProperty('name')
    expect(payload.auth_time).toBeNumber()
  })

  // OIDC DCR 1.0 §2: the client's registered algorithm, not the provider's default.
  test('an ID token is signed with the algorithm the client registered', async () => {
    await adapter.clients.upsert?.({ ...((await adapter.clients.find('rp')) as Client), idTokenSignedResponseAlg: 'RS256' })
    const { location } = await loginAndConsent()
    const body = await (await exchange(location.searchParams.get('code') as string)).json()
    expect(decodeProtectedHeader(body.id_token).alg).toBe('RS256')
  })

  test('a token response signs its ID token and JWT access token from one key read', async () => {
    await adapter.clients.upsert?.({ ...((await adapter.clients.find('rp')) as Client), accessTokenFormat: 'jwt' })
    let reads = 0
    const counted = {
      ...adapter,
      keys: {
        active: () => {
          reads++
          return adapter.keys.active()
        }
      }
    }
    drive(createProvider({ issuer: ISSUER, adapter: counted, interactionUrl: `${ISSUER}/interaction` }))
    const { location } = await loginAndConsent()
    reads = 0
    const body = await (await exchange(location.searchParams.get('code') as string)).json()
    expect(body.id_token).toBeString()
    expect(body.access_token.split('.')).toHaveLength(3)
    expect(reads).toBe(1)
  })

  test('a wrong code_verifier is refused', async () => {
    const { location } = await loginAndConsent()
    const response = await exchange(location.searchParams.get('code') as string, { code_verifier: randomString() + randomString() })
    expect(response.status).toBe(400)
    expect((await response.json()).error).toBe('invalid_grant')
  })

  test('a mismatched redirect_uri is refused', async () => {
    const { location } = await loginAndConsent()
    const response = await exchange(location.searchParams.get('code') as string, { redirect_uri: 'https://rp.example.com/other' })
    expect((await response.json()).error).toBe('invalid_grant')
  })

  // FR-T4 / RFC 9700 §4.14.2: the replay revokes everything the code produced.
  test('replaying an authorization code revokes everything it produced', async () => {
    const { location } = await loginAndConsent()
    const code = location.searchParams.get('code') as string
    const first = await (await exchange(code)).json()

    const replay = await exchange(code)
    expect(replay.status).toBe(400)
    expect((await replay.json()).error_description).toContain('revoked')

    const refresh = await post('/token', { grant_type: 'refresh_token', refresh_token: first.refresh_token }, { authorization: basic() })
    expect((await refresh.json()).error).toBe('invalid_grant')
  })

  // NFR-S4: two redemptions in flight at once — one wins, the other is a replay and revokes what it produced.
  test('parallel redemptions of one code yield one token set and revoke it', async () => {
    const { location } = await loginAndConsent()
    const code = location.searchParams.get('code') as string
    const responses = await Promise.all([exchange(code), exchange(code)])
    const won = responses.filter(response => response.status === 200)
    expect(won.length).toBeLessThanOrEqual(1)
    expect(responses.filter(response => response.status === 400).length).toBeGreaterThanOrEqual(1)

    // Whichever order the two ran in, nothing the code produced still works (NFR-S4).
    for (const response of won) {
      const winner = await response.json()
      const refresh = await post('/token', { grant_type: 'refresh_token', refresh_token: winner.refresh_token }, { authorization: basic() })
      expect((await refresh.json()).error).toBe('invalid_grant')
      const userinfo = await provider.handle(
        new Request(`${ISSUER}/userinfo`, { headers: { authorization: `Bearer ${winner.access_token}` } })
      )
      expect(userinfo.status).toBe(401)
    }
  })

  test('parallel refreshes of one token cannot fork the family', async () => {
    const { location } = await loginAndConsent()
    const first = await (await exchange(location.searchParams.get('code') as string)).json()
    const refresh = () => post('/token', { grant_type: 'refresh_token', refresh_token: first.refresh_token }, { authorization: basic() })
    const responses = await Promise.all([refresh(), refresh()])
    const won = responses.filter(response => response.status === 200)
    expect(won.length).toBeLessThanOrEqual(1)
    for (const response of won) {
      const { refresh_token } = await response.json()
      const again = await post('/token', { grant_type: 'refresh_token', refresh_token }, { authorization: basic() })
      expect((await again.json()).error).toBe('invalid_grant')
    }
  })

  // FR-T3: rotation is unconditional.
  test('a refresh rotates the token and replaying the old one revokes its family', async () => {
    const { location } = await loginAndConsent()
    const first = await (await exchange(location.searchParams.get('code') as string)).json()

    const rotated = await (
      await post('/token', { grant_type: 'refresh_token', refresh_token: first.refresh_token }, { authorization: basic() })
    ).json()
    expect(rotated.refresh_token).toBeTruthy()
    expect(rotated.refresh_token).not.toBe(first.refresh_token)

    const replay = await post('/token', { grant_type: 'refresh_token', refresh_token: first.refresh_token }, { authorization: basic() })
    expect((await replay.json()).error).toBe('invalid_grant')

    const afterRevocation = await post(
      '/token',
      { grant_type: 'refresh_token', refresh_token: rotated.refresh_token },
      { authorization: basic() }
    )
    expect((await afterRevocation.json()).error).toBe('invalid_grant')
  })

  // FR-T3, FR-T4, FR-C8: one grant per account and client, one family per authorization.
  describe('the same app on two devices', () => {
    const twoDevices = async () => {
      const { location, cookie } = await loginAndConsent()
      const phoneCode = location.searchParams.get('code') as string
      const phone = await (await exchange(phoneCode)).json()
      const again = await go(authorizeUrl(), cookie)
      const laptop = await (await exchange(new URL(again.headers.get('location') as string).searchParams.get('code') as string)).json()
      return { phone, phoneCode, laptop }
    }
    const refresh = (refresh_token: string) => post('/token', { grant_type: 'refresh_token', refresh_token }, { authorization: basic() })
    const userinfo = (token: string) =>
      provider.handle(new Request(`${ISSUER}/userinfo`, { headers: { authorization: `Bearer ${token}` } }))

    const stored = async (kind: 'access_token' | 'refresh_token', token: string) =>
      adapter.artifacts.find(kind, base64url.encode(await sha256(token)))

    test('share one grant', async () => {
      const { phone, laptop } = await twoDevices()
      const phoneToken = await stored('refresh_token', phone.refresh_token)
      const laptopToken = await stored('refresh_token', laptop.refresh_token)
      expect(phoneToken?.grantId).toBe(laptopToken?.grantId as string)
      expect(phoneToken?.familyId).toBeString()
      expect(phoneToken?.familyId).not.toBe(laptopToken?.familyId as string)
    })

    test('a replayed refresh token ends its own device and not the other', async () => {
      const { phone, laptop } = await twoDevices()
      expect((await refresh(phone.refresh_token)).status).toBe(200)
      expect((await (await refresh(phone.refresh_token)).json()).error).toBe('invalid_grant')

      expect((await userinfo(phone.access_token)).status).toBe(401)
      expect((await userinfo(laptop.access_token)).status).toBe(200)
      expect((await refresh(laptop.refresh_token)).status).toBe(200)
    })

    test('a replayed code ends what it produced and not the other', async () => {
      const { phone, phoneCode, laptop } = await twoDevices()
      expect((await exchange(phoneCode)).status).toBe(400)

      expect((await userinfo(phone.access_token)).status).toBe(401)
      expect((await (await refresh(phone.refresh_token)).json()).error).toBe('invalid_grant')
      expect((await userinfo(laptop.access_token)).status).toBe(200)
      expect((await refresh(laptop.refresh_token)).status).toBe(200)
    })

    test('revoking one device’s refresh token signs that device out and not the other', async () => {
      const { phone, laptop } = await twoDevices()
      expect((await post('/revoke', { token: phone.refresh_token }, { authorization: basic() })).status).toBe(200)

      expect((await userinfo(phone.access_token)).status).toBe(401)
      expect((await (await refresh(phone.refresh_token)).json()).error).toBe('invalid_grant')
      expect((await userinfo(laptop.access_token)).status).toBe(200)
      expect((await refresh(laptop.refresh_token)).status).toBe(200)
    })

    test('a rotated refresh token stays in its family', async () => {
      const { phone } = await twoDevices()
      const rotated = await (await refresh(phone.refresh_token)).json()
      const before = await stored('access_token', phone.access_token)
      const after = await stored('refresh_token', rotated.refresh_token)
      expect(after?.familyId).toBeString()
      expect(after?.familyId).toBe(before?.familyId as string)
    })
  })

  test('a refresh may narrow the scope but never widen it', async () => {
    const { location } = await loginAndConsent()
    const first = await (await exchange(location.searchParams.get('code') as string)).json()
    const widened = await post(
      '/token',
      { grant_type: 'refresh_token', refresh_token: first.refresh_token, scope: 'openid email' },
      { authorization: basic() }
    )
    expect((await widened.json()).error).toBe('invalid_scope')
  })

  // RFC 6749 §6: narrowing the access token must not cost the client its refresh token.
  test('a narrowed refresh still rotates a refresh token of the original scope', async () => {
    const { location } = await loginAndConsent()
    const first = await (await exchange(location.searchParams.get('code') as string)).json()
    const narrowed = await (
      await post('/token', { grant_type: 'refresh_token', refresh_token: first.refresh_token, scope: 'openid' }, { authorization: basic() })
    ).json()
    expect(narrowed.scope).toBe('openid')
    expect(narrowed.refresh_token).toBeTruthy()

    const full = await (
      await post('/token', { grant_type: 'refresh_token', refresh_token: narrowed.refresh_token }, { authorization: basic() })
    ).json()
    expect(full.scope).toBe('openid profile offline_access')
  })

  test('a scope withdrawn from the grant does not come back on refresh', async () => {
    const { location } = await loginAndConsent()
    const first = await (await exchange(location.searchParams.get('code') as string)).json()
    const grant = await adapter.grants.findByAccountAndClient('ada', 'rp')
    await adapter.grants.upsert({ ...(grant as NonNullable<typeof grant>), scopes: ['openid', 'offline_access'] })

    const refreshed = await (
      await post('/token', { grant_type: 'refresh_token', refresh_token: first.refresh_token }, { authorization: basic() })
    ).json()
    expect(refreshed.scope).toBe('openid offline_access')
  })

  test('a bad client secret is rejected', async () => {
    const { location } = await loginAndConsent()
    const response = await exchange(location.searchParams.get('code') as string, {})
    expect(response.status).toBe(200)
    const bad = await post(
      '/token',
      { grant_type: 'authorization_code', code: 'x', redirect_uri: REDIRECT, code_verifier: verifier },
      { authorization: basic('rp', 'wrong') }
    )
    expect(bad.status).toBe(401)
    expect((await bad.json()).error).toBe('invalid_client')
  })

  test('credentials in both the header and the body are refused rather than resolved', async () => {
    const response = await post(
      '/token',
      { grant_type: 'authorization_code', code: 'x', client_id: 'rp', client_secret: 'shhh-a-long-enough-secret' },
      { authorization: basic() }
    )
    expect(response.status).toBe(401)
    expect((await response.json()).error_description).toContain('both')
  })

  test('an unknown grant_type is refused', async () => {
    const response = await post('/token', { grant_type: 'password', username: 'a', password: 'b' }, { authorization: basic() })
    expect((await response.json()).error).toBe('unauthorized_client')
  })
})
