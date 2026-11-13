import { describe, expect, test } from 'bun:test'
import { createLocalJWKSet, decodeJwt, decodeProtectedHeader, generateKeyPair, jwtVerify } from 'jose'
import { withHashedArtifacts } from '../artifacts'
import { adapter, basic, build, client, ISSUER, tokensFor, useFlow } from '../test-flow'

useFlow()

describe('FR-T2: JWT access tokens', () => {
  test('opaque by default', async () => {
    await adapter.clients.upsert?.(client())
    const issued = await tokensFor(build())
    expect(issued.access_token.split('.')).toHaveLength(1)
  })

  test('a client can opt into RFC 9068 format', async () => {
    await adapter.clients.upsert?.(client({ accessTokenFormat: 'jwt' }))
    const provider = build()
    const issued = await tokensFor(provider)

    expect(decodeProtectedHeader(issued.access_token).typ).toBe('at+jwt')
    const jwks = await (await provider.handle(new Request(`${ISSUER}/jwks`))).json()
    const { payload } = await jwtVerify(issued.access_token, createLocalJWKSet(jwks), { issuer: ISSUER })
    expect(payload.sub).toBe('ada')
    expect(payload.client_id).toBe('rp')
    expect(payload.scope).toBe('openid profile')
    expect(payload.jti).toBeTruthy()
  })

  // The whole argument for opaque-by-default is that revocation must still bite.
  test('a JWT access token is still revocable, because the jti is the stored record', async () => {
    await adapter.clients.upsert?.(client({ accessTokenFormat: 'jwt' }))
    const provider = build()
    const issued = await tokensFor(provider)

    const before = await provider.handle(new Request(`${ISSUER}/userinfo`, { headers: { authorization: `Bearer ${issued.access_token}` } }))
    expect(before.status).toBe(200)

    const revoked = await provider.handle(
      new Request(`${ISSUER}/revoke`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: basic() },
        body: new URLSearchParams({ token: issued.access_token }).toString()
      })
    )
    expect(revoked.status).toBe(200)
    expect(await withHashedArtifacts(adapter).artifacts.find('access_token', decodeJwt(issued.access_token).jti as string)).toBeUndefined()

    const after = await provider.handle(new Request(`${ISSUER}/userinfo`, { headers: { authorization: `Bearer ${issued.access_token}` } }))
    expect(after.status).toBe(401)
  })

  test('a JWT access token can be introspected', async () => {
    await adapter.clients.upsert?.(client({ accessTokenFormat: 'jwt' }))
    const provider = build()
    const issued = await tokensFor(provider)
    const introspect = async (token: string) =>
      (
        await provider.handle(
          new Request(`${ISSUER}/introspect`, {
            method: 'POST',
            headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: basic() },
            body: new URLSearchParams({ token }).toString()
          })
        )
      ).json()

    expect(await introspect(issued.access_token)).toMatchObject({ active: true, client_id: 'rp', scope: 'openid profile' })
    await withHashedArtifacts(adapter).artifacts.destroy('access_token', decodeJwt(issued.access_token).jti as string)
    expect(await introspect(issued.access_token)).toEqual({ active: false })
  })

  test('a JWT this provider did not issue is not accepted', async () => {
    await adapter.clients.upsert?.(client())
    const provider = build()
    const foreign = await new (await import('jose')).SignJWT({ jti: 'made-up' })
      .setProtectedHeader({ alg: 'ES256', typ: 'at+jwt' })
      .setIssuer('https://evil.example.net')
      .setExpirationTime('5m')
      .sign((await generateKeyPair('ES256', { extractable: true })).privateKey)
    const response = await provider.handle(new Request(`${ISSUER}/userinfo`, { headers: { authorization: `Bearer ${foreign}` } }))
    expect(response.status).toBe(401)
  })
})

describe('one way to make an access token', () => {
  // FR-T2: the client chose the format; which grant produced the token does not change that.
  test('client_credentials honours a client opted into JWT access tokens', async () => {
    await adapter.clients.upsert?.(client({ accessTokenFormat: 'jwt', grantTypes: ['client_credentials'], scopes: ['profile'] }))
    const body = await (
      await build().handle(
        new Request(`${ISSUER}/token`, {
          method: 'POST',
          headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: basic() },
          body: 'grant_type=client_credentials'
        })
      )
    ).json()
    expect(decodeProtectedHeader(body.access_token).typ).toBe('at+jwt')
    expect(await withHashedArtifacts(adapter).artifacts.find('access_token', decodeJwt(body.access_token).jti as string)).toBeTruthy()
  })
})
