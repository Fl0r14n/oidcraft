import { describe, expect, test } from 'bun:test'
import { exportJWK, generateKeyPair, SignJWT } from 'jose'
import { memoryAdapter } from '../adapters/memory'
import { issuerOf, upstreamLogout } from './logout'
import type { UpstreamProvider } from './types'

const provider: UpstreamProvider = {
  id: 'entra',
  issuer: 'https://login.example.com',
  clientId: 'broker',
  scopes: ['openid']
}

const signing = await generateKeyPair('ES256', { extractable: true })
const jwks = { keys: [await exportJWK(signing.publicKey)] }

const LOGOUT_EVENT = 'http://schemas.openid.net/event/backchannel-logout'

const logoutToken = (claims: Record<string, unknown>, over: { issuer?: string; audience?: string; typ?: string } = {}) =>
  new SignJWT({ events: { [LOGOUT_EVENT]: {} }, jti: crypto.randomUUID(), ...claims })
    .setProtectedHeader({ alg: 'ES256', typ: over.typ ?? 'logout+jwt' })
    .setIssuer(over.issuer ?? provider.issuer)
    .setAudience(over.audience ?? provider.clientId)
    .setIssuedAt()
    .setExpirationTime('2m')
    .sign(signing.privateKey)

const withSessions = async () => {
  const adapter = await memoryAdapter()
  await adapter.sessions.upsert({
    id: 'local-1',
    accountId: 'ada',
    authTime: new Date(),
    idp: 'entra',
    upstreamSessionId: 'up-1',
    clients: ['rp'],
    expiresAt: new Date(Date.now() + 60_000)
  })
  await adapter.sessions.upsert({
    id: 'local-2',
    accountId: 'bob',
    authTime: new Date(),
    idp: 'entra',
    upstreamSessionId: 'up-2',
    clients: ['rp'],
    expiresAt: new Date(Date.now() + 60_000)
  })
  return adapter
}

describe('upstream back-channel logout', () => {
  // FR-F8: the token arrives keyed by *their* session id, which is why we record it.
  test('finds the local sessions an upstream session produced', async () => {
    const adapter = await withSessions()
    const result = await upstreamLogout(adapter, provider, await logoutToken({ sid: 'up-1', sub: 'ada' }), jwks)
    expect(result.sessions.map(session => session.id)).toEqual(['local-1'])
  })

  test('falls back to the linked account when only sub is given', async () => {
    const adapter = await withSessions()
    await adapter.identities.upsert({ accountId: 'ada', provider: 'entra', subject: 'up-sub', claims: {}, linkedAt: new Date() })
    const result = await upstreamLogout(adapter, provider, await logoutToken({ sub: 'up-sub' }), jwks)
    expect(result.sessions.map(session => session.id)).toEqual(['local-1'])
  })

  // Accepting one without the events claim would let a replayed ID token end sessions.
  test('a token without the logout event is refused', async () => {
    const adapter = await withSessions()
    const notALogout = await new SignJWT({ sid: 'up-1', jti: crypto.randomUUID() })
      .setProtectedHeader({ alg: 'ES256' })
      .setIssuer(provider.issuer)
      .setAudience(provider.clientId)
      .setIssuedAt()
      .setExpirationTime('2m')
      .sign(signing.privateKey)
    expect(upstreamLogout(adapter, provider, notALogout, jwks)).rejects.toThrow(/not a logout token/)
  })

  // §2.6: accepted once, or a captured token could end the sessions of every later sign-in.
  test('a replayed logout token is refused', async () => {
    const adapter = await withSessions()
    const token = await logoutToken({ sid: 'up-1' })
    await upstreamLogout(adapter, provider, token, jwks)
    await expect(upstreamLogout(adapter, provider, token, jwks)).rejects.toThrow(/already used/)
  })

  test('a token without jti, typed as something else, or with a non-object event is refused', async () => {
    const adapter = await withSessions()
    await expect(upstreamLogout(adapter, provider, await logoutToken({ sid: 'up-1', jti: undefined }), jwks)).rejects.toThrow(/jti/)
    await expect(upstreamLogout(adapter, provider, await logoutToken({ sid: 'up-1' }, { typ: 'JWT' }), jwks)).rejects.toThrow(
      /typed logout\+jwt/
    )
    await expect(
      upstreamLogout(adapter, provider, await logoutToken({ sid: 'up-1', events: { [LOGOUT_EVENT]: true } }), jwks)
    ).rejects.toThrow(/not a logout token/)
  })

  test('a logout token carrying a nonce is refused', async () => {
    const adapter = await withSessions()
    expect(upstreamLogout(adapter, provider, await logoutToken({ sid: 'up-1', nonce: 'n' }), jwks)).rejects.toThrow(
      /must not carry a nonce/
    )
  })

  test('a token from another issuer or for another audience is refused', async () => {
    const adapter = await withSessions()
    expect(
      upstreamLogout(adapter, provider, await logoutToken({ sid: 'up-1' }, { issuer: 'https://evil.example' }), jwks)
    ).rejects.toThrow()
    expect(upstreamLogout(adapter, provider, await logoutToken({ sid: 'up-1' }, { audience: 'someone-else' }), jwks)).rejects.toThrow()
  })

  test('a token signed by the wrong key is refused', async () => {
    const adapter = await withSessions()
    const other = await generateKeyPair('ES256', { extractable: true })
    const forged = await new SignJWT({ events: { [LOGOUT_EVENT]: {} }, sid: 'up-1' })
      .setProtectedHeader({ alg: 'ES256' })
      .setIssuer(provider.issuer)
      .setAudience(provider.clientId)
      .setIssuedAt()
      .setExpirationTime('2m')
      .sign(other.privateKey)
    expect(upstreamLogout(adapter, provider, forged, jwks)).rejects.toThrow()
  })

  test('a token with neither sid nor sub is refused', async () => {
    const adapter = await withSessions()
    expect(upstreamLogout(adapter, provider, await logoutToken({}), jwks)).rejects.toThrow(/needs sid or sub/)
  })

  test('an unknown upstream session ends nothing rather than everything', async () => {
    const adapter = await withSessions()
    const result = await upstreamLogout(adapter, provider, await logoutToken({ sid: 'never-seen' }), jwks)
    expect(result.sessions).toEqual([])
  })

  // Reading it before trusting it is how the right keys get chosen.
  test('the issuer can be read before the token is verified', async () => {
    expect(issuerOf(await logoutToken({ sid: 'up-1' }))).toBe(provider.issuer)
    expect(issuerOf('not a jwt')).toBeUndefined()
  })
})
