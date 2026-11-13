import { describe, expect, test } from 'bun:test'
import { compactDecrypt, createLocalJWKSet, decodeJwt, exportJWK, generateKeyPair, jwtVerify } from 'jose'
import {
  adapter,
  basic,
  build,
  client,
  ISSUER,
  loginAndConsent,
  post,
  provider,
  REDIRECT,
  tokensFor,
  useFlow,
  verifier
} from '../test-flow'

useFlow()

describe('userinfo', () => {
  test('returns the claims the granted scopes release', async () => {
    const { location } = await loginAndConsent()
    const tokens = await (
      await post(
        '/token',
        {
          grant_type: 'authorization_code',
          code: location.searchParams.get('code') as string,
          redirect_uri: REDIRECT,
          code_verifier: verifier
        },
        { authorization: basic() }
      )
    ).json()

    const response = await provider.handle(
      new Request(`${ISSUER}/userinfo`, { headers: { authorization: `Bearer ${tokens.access_token}` } })
    )
    expect(response.status).toBe(200)
    const body = await response.json()
    expect(body.sub).toBe('ada')
    expect(body.name).toBe('Ada Lovelace')
  })

  test('an unknown token is 401 with a WWW-Authenticate challenge', async () => {
    const response = await provider.handle(new Request(`${ISSUER}/userinfo`, { headers: { authorization: 'Bearer nope' } }))
    expect(response.status).toBe(401)
    expect(response.headers.get('www-authenticate')).toContain('Bearer')
  })

  test('no token at all is 401', async () => {
    expect((await provider.handle(new Request(`${ISSUER}/userinfo`))).status).toBe(401)
  })
})

describe('FR-C5: signed and encrypted UserInfo', () => {
  test('a signed response is a JWT the client can verify', async () => {
    await adapter.clients.upsert?.(client({ userinfoSignedResponseAlg: 'ES256' }))
    const provider = build()
    const issued = await tokensFor(provider)

    const response = await provider.handle(
      new Request(`${ISSUER}/userinfo`, { headers: { authorization: `Bearer ${issued.access_token}` } })
    )
    expect(response.headers.get('content-type')).toContain('application/jwt')

    const jwks = await (await provider.handle(new Request(`${ISSUER}/jwks`))).json()
    const { payload } = await jwtVerify(await response.text(), createLocalJWKSet(jwks), { issuer: ISSUER, audience: 'rp' })
    expect(payload.sub).toBe('ada')
    expect(payload.name).toBe('Ada Lovelace')
  })

  test('an encrypted response is a JWE the client can decrypt', async () => {
    const encryption = await generateKeyPair('RSA-OAEP-256', { extractable: true })
    const publicJwk = { ...(await exportJWK(encryption.publicKey)), use: 'enc', alg: 'RSA-OAEP-256' }
    await adapter.clients.upsert?.(
      client({
        userinfoSignedResponseAlg: 'ES256',
        userinfoEncryptedResponseAlg: 'RSA-OAEP-256',
        userinfoEncryptedResponseEnc: 'A128CBC-HS256',
        jwks: { keys: [publicJwk] }
      })
    )
    const provider = build()
    const issued = await tokensFor(provider)

    const response = await provider.handle(
      new Request(`${ISSUER}/userinfo`, { headers: { authorization: `Bearer ${issued.access_token}` } })
    )
    const { plaintext } = await compactDecrypt(await response.text(), encryption.privateKey)
    const inner = new TextDecoder().decode(plaintext)
    expect(decodeJwt(inner).name).toBe('Ada Lovelace')
  })

  test('plain JSON when the client asked for neither', async () => {
    await adapter.clients.upsert?.(client())
    const provider = build()
    const issued = await tokensFor(provider)
    const response = await provider.handle(
      new Request(`${ISSUER}/userinfo`, { headers: { authorization: `Bearer ${issued.access_token}` } })
    )
    expect(response.headers.get('content-type')).toContain('application/json')
  })
})

describe('UserInfo answers a bad token as RFC 6750 names it', () => {
  test('invalid_token in the body as in the challenge', async () => {
    const response = await build().handle(new Request(`${ISSUER}/userinfo`, { headers: { authorization: 'Bearer nope' } }))
    expect(response.status).toBe(401)
    expect(response.headers.get('www-authenticate')).toContain('error="invalid_token"')
    expect((await response.json()).error).toBe('invalid_token')
  })

  test('no token at all is invalid_request', async () => {
    const response = await build().handle(new Request(`${ISSUER}/userinfo`))
    expect((await response.json()).error).toBe('invalid_request')
  })
})
