import { afterAll, beforeAll, describe, expect, it } from 'bun:test'
import { exportJWK, generateKeyPair, SignJWT } from 'jose'
import { createJwt } from './jwt'
import { idToken } from './test-utils'

// no jwksUri + strictJwt off → the local parseJwt path is exercised
const jwt = createJwt({ config: () => ({}) as any, strictJwt: () => false })

describe('jwt parse (no jwks)', () => {
  it('returns {} without a token', async () => {
    expect(await jwt()).toEqual({})
  })

  it('parses a plain ascii payload', async () => {
    const payload = { sub: 'abc', admin: true }
    expect(await jwt(idToken(payload))).toEqual(payload)
  })

  it('parses base64url payloads containing - and _', async () => {
    const payload = { sub: '1234567890', name: 'ÿÿÿ' } // utf-8 bytes hit the base64url -/_ alphabet
    const token = idToken(payload)
    expect(token.split('.')[1]).toMatch(/[-_]/) // guard: the regression is actually exercised
    expect(await jwt(token)).toEqual(payload)
  })

  it('parses unpadded payload lengths', async () => {
    // vary payload length so the stripped base64 padding must be reconstructed
    for (const name of ['a', 'ab', 'abc', 'abcd']) {
      const payload = { name }
      expect(await jwt(idToken(payload))).toEqual(payload)
    }
  })

  it('returns {} for a malformed token rather than throwing', async () => {
    expect(await jwt('not-a-jwt')).toEqual({})
  })
})

describe('jwt verify (jwks configured)', () => {
  const ISSUER = 'https://idp'
  const AUDIENCE = 'c'

  // a real JWKS over a real socket, so nothing here depends on the machine's network and nothing
  // fails at the transport layer — the assertions are about verification, so a connection error
  // would be the wrong reason to pass. `allowInsecure` because that socket is http, and the guard
  // that would otherwise refuse it is the point of `secure.ts`.
  let server: ReturnType<typeof Bun.serve>
  let signed: string
  let signedByStranger: string
  let status = 200
  let keys: object[] = []

  beforeAll(async () => {
    const mine = await generateKeyPair('RS256')
    const stranger = await generateKeyPair('RS256')
    keys = [{ ...(await exportJWK(mine.publicKey)), alg: 'RS256', kid: 'mine' }]

    const sign = (key: CryptoKey, kid: string) =>
      new SignJWT({ sub: 'abc', name: 'Jane' })
        .setProtectedHeader({ alg: 'RS256', kid })
        .setIssuer(ISSUER)
        .setAudience(AUDIENCE)
        .setExpirationTime('5m')
        .sign(key)

    signed = await sign(mine.privateKey, 'mine')
    signedByStranger = await sign(stranger.privateKey, 'stranger')

    server = Bun.serve({
      port: 0,
      fetch: () => (status === 200 ? Response.json({ keys }) : new Response('nope', { status }))
    })
  })

  afterAll(() => server.stop(true))

  const strictJwt = () =>
    createJwt({
      config: () =>
        ({ jwksUri: `http://localhost:${server.port}/jwks`, issuerPath: ISSUER, clientId: AUDIENCE, allowInsecure: true }) as any,
      strictJwt: () => true
    })

  it('returns the payload for a token the jwks verifies', async () => {
    status = 200
    const payload = await strictJwt()(signed)

    expect(payload?.sub).toBe('abc')
    expect(payload?.name).toBe('Jane')
    expect(payload?.error).toBeUndefined()
  })

  it('rejects a token signed by a key the jwks does not carry', async () => {
    status = 200

    expect(await strictJwt()(signedByStranger)).toEqual({ error: 'Invalid token' })
  })

  it('rejects rather than falling back to the unsigned parse when the jwks cannot be fetched', async () => {
    status = 500

    // the important half: a token that *would* parse locally must not be trusted just because the
    // key set was unavailable
    expect(await strictJwt()(signed)).toEqual({ error: 'Invalid token' })
    expect(await strictJwt()(idToken({ sub: 'abc' }))).toEqual({ error: 'Invalid token' })
  })

  it('rejects a token whose issuer or audience does not match the config', async () => {
    status = 200
    const wrongAudience = createJwt({
      config: () =>
        ({ jwksUri: `http://localhost:${server.port}/jwks`, issuerPath: ISSUER, clientId: 'someone-else', allowInsecure: true }) as any,
      strictJwt: () => true
    })

    expect(await wrongAudience(signed)).toEqual({ error: 'Invalid token' })
  })
})
