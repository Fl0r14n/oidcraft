import { afterEach, describe, expect, it, jest } from 'bun:test'
import { exportJWK, generateKeyPair, SignJWT } from 'jose'
import { beginAuthorization, completeAuthorization as complete, completeAuthorization } from './flow'
import type { IdTokenVerifier } from './jwt'
import { OAuthType } from './types'

const config = { authorizePath: 'https://auth.com/authorize', tokenPath: 'https://auth.com/token', clientId: 'client123', scope: 'openid' }

const parameters = { redirectUri: 'https://app.com/cb', responseType: 'code' }

const claims =
  (payload: Record<string, any>): IdTokenVerifier =>
  async () =>
    payload

describe('beginAuthorization', () => {
  it('returns the url and the handoff, and performs nothing', async () => {
    const { url, handoff } = await beginAuthorization(config, parameters)

    expect(url).toContain('https://auth.com/authorize?')
    expect(handoff.state).toBeTruthy()
  })

  it('routes through an overridden authorizationUrl', async () => {
    const authorizationUrl = jest.fn().mockResolvedValue({ url: 'https://elsewhere', handoff: { redirect_uri: 'x' } })

    const request = await beginAuthorization(config, parameters, { functions: { authorizationUrl } })

    expect(authorizationUrl).toHaveBeenCalledWith(parameters, config)
    expect(request.url).toBe('https://elsewhere')
  })
})

describe('completeAuthorization', () => {
  it('ignores a url that is not a redirect back', async () => {
    expect(await completeAuthorization(config, 'https://app.com/cb', { state: 's' })).toBeUndefined()
  })

  it('exchanges the code with the handoff the request was started with', async () => {
    const authorize = jest.fn().mockResolvedValue({ access_token: 'at', type: OAuthType.AUTHORIZATION_CODE })
    const handoff = { redirect_uri: 'https://app.com/cb', state: 's1', code_verifier: 'v1' }

    const token = await completeAuthorization(config, 'https://app.com/cb?code=c1&state=s1', handoff, {
      functions: { authorize },
      verifyIdToken: claims({})
    })

    expect(authorize).toHaveBeenCalledWith(
      expect.objectContaining({ code: 'c1', code_verifier: 'v1', redirect_uri: 'https://app.com/cb' }),
      config
    )
    expect(token).toMatchObject({ access_token: 'at' })
  })

  it('refuses a state that is not the one it issued', async () => {
    const authorize = jest.fn()

    const token = await completeAuthorization(
      config,
      'https://app.com/cb?code=c1&state=forged',
      { state: 's1' },
      { functions: { authorize } }
    )

    expect(token).toEqual({ error: 'Invalid state' })
    // the point of checking first: a forged callback must not burn a code at the token endpoint
    expect(authorize).not.toHaveBeenCalled()
  })

  it('leaves the check alone when it issued no state', async () => {
    const authorize = jest.fn().mockResolvedValue({ access_token: 'at' })

    const token = await completeAuthorization(
      config,
      'https://app.com/cb?code=c1&state=s9',
      {},
      {
        functions: { authorize },
        verifyIdToken: claims({})
      }
    )

    expect(token).toMatchObject({ access_token: 'at' })
  })

  it('passes an error response through when the provider dropped the state from it', async () => {
    const token = await completeAuthorization(
      config,
      'https://app.com/cb?error=access_denied',
      { state: 's1' },
      {
        functions: { authorize: async t => t }
      }
    )

    expect(token).toMatchObject({ error: 'access_denied' })
  })

  it('still refuses a forged error that carries the wrong state', async () => {
    const token = await completeAuthorization(config, 'https://app.com/cb?error=access_denied&state=forged', { state: 's1' })

    expect(token).toEqual({ error: 'Invalid state' })
  })

  it('checks the nonce against the handoff on the implicit response', async () => {
    const source = 'https://app.com/cb#access_token=at&id_token=header.payload.sig'

    const ok = await completeAuthorization(config, source, { nonce: 'n1' }, { verifyIdToken: claims({ nonce: 'n1' }) })
    expect(ok).toMatchObject({ access_token: 'at', type: OAuthType.IMPLICIT })

    const bad = await completeAuthorization(config, source, { nonce: 'n1' }, { verifyIdToken: claims({ nonce: 'other' }) })
    expect(bad).toMatchObject({ error: 'Invalid nonce', type: OAuthType.IMPLICIT })
  })

  it('reports a rejected id token rather than the nonce it could not read', async () => {
    const token = await completeAuthorization(
      config,
      'https://app.com/cb#access_token=at&id_token=h.p.s',
      { nonce: 'n1' },
      {
        verifyIdToken: claims({ error: 'Invalid token' })
      }
    )

    expect(token).toMatchObject({ error: 'Invalid token' })
  })

  it('keeps what the redirect carried when the exchange yields nothing', async () => {
    const token = await completeAuthorization(
      config,
      'https://app.com/cb?code=c1',
      { redirect_uri: 'https://app.com/cb' },
      {
        functions: { authorize: async () => undefined }
      }
    )

    expect(token).toMatchObject({ code: 'c1', redirect_uri: 'https://app.com/cb' })
  })

  it('keeps two callbacks apart — the handoff is an argument, not a lookup', async () => {
    const authorize = jest.fn(async (token: any) => ({ access_token: `at-${token.code_verifier}` }))
    const verifyIdToken = claims({})

    const [one, two] = await Promise.all([
      completeAuthorization(
        config,
        'https://app.com/cb?code=c1&state=s1',
        { state: 's1', code_verifier: 'v1' },
        {
          functions: { authorize },
          verifyIdToken
        }
      ),
      completeAuthorization(
        config,
        'https://app.com/cb?code=c2&state=s2',
        { state: 's2', code_verifier: 'v2' },
        {
          functions: { authorize },
          verifyIdToken
        }
      )
    ])

    expect(one).toMatchObject({ access_token: 'at-v1' })
    expect(two).toMatchObject({ access_token: 'at-v2' })
  })
})

// the leg k2's oauth app runs: a confidential client federating to Entra's /common endpoint, whose
// discovery document asserts a {tenantid} template rather than an issuer
describe('completeAuthorization against a multi-tenant provider', () => {
  const TENANT = '9188040d-6c67-4c5b-b112-36a304b66dad'
  const realFetch = globalThis.fetch

  afterEach(() => {
    globalThis.fetch = realFetch
  })

  const entra = async (tid: string) => {
    const pair = await generateKeyPair('ES256', { extractable: true })
    const jwks = { keys: [{ ...(await exportJWK(pair.publicKey)), alg: 'ES256', kid: 'k1' }] }
    globalThis.fetch = jest.fn(async () => new Response(JSON.stringify(jwks))) as any
    const id_token = await new SignJWT({ iss: `https://login.microsoftonline.com/${tid}/v2.0`, tid, sub: 'u1', nonce: 'n1' })
      .setProtectedHeader({ alg: 'ES256', kid: 'k1' })
      .setIssuedAt()
      .setExpirationTime('5m')
      .setAudience('client123')
      .sign(pair.privateKey)
    return id_token
  }

  const config = {
    clientId: 'client123',
    clientSecret: 'shh',
    tokenPath: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
    issuerPath: 'https://login.microsoftonline.com/common/v2.0',
    issuer: 'https://login.microsoftonline.com/{tenantid}/v2.0',
    jwksUri: 'https://login.microsoftonline.com/common/discovery/v2.0/keys'
  }

  it('verifies the id token against the tenant it names', async () => {
    const id_token = await entra(TENANT)
    const authorize = async () => ({ access_token: 'at', id_token })

    const token = await complete(
      config,
      'https://k2/oauth/microsoft/callback?code=c1&state=s1',
      { state: 's1', nonce: 'n1' },
      {
        functions: { authorize }
      }
    )

    expect(token).toMatchObject({ access_token: 'at' })
  })

  it('still rejects a token from a tenant the issuer template cannot produce', async () => {
    const pair = await generateKeyPair('ES256', { extractable: true })
    const jwks = { keys: [{ ...(await exportJWK(pair.publicKey)), alg: 'ES256', kid: 'k1' }] }
    globalThis.fetch = jest.fn(async () => new Response(JSON.stringify(jwks))) as any
    const id_token = await new SignJWT({ iss: 'https://login.microsoftonline.com/attacker/v2.0', tid: TENANT, sub: 'u1', nonce: 'n1' })
      .setProtectedHeader({ alg: 'ES256', kid: 'k1' })
      .setIssuedAt()
      .setExpirationTime('5m')
      .setAudience('client123')
      .sign(pair.privateKey)

    const token = await completeAuthorization(
      config,
      'https://k2/oauth/microsoft/callback?code=c1&state=s1',
      { state: 's1', nonce: 'n1' },
      {
        functions: { authorize: async () => ({ access_token: 'at', id_token }) }
      }
    )

    expect(token).toEqual({ error: 'Invalid token' })
  })
})

/**
 * RFC 9207 §2.4. With more than one provider configured, a code minted by an attacker's
 * authorization server is otherwise indistinguishable from one minted by the honest one, and gets
 * exchanged at the honest one's token endpoint — the mix-up attack.
 */
describe('completeAuthorization: the iss on the authorization response', () => {
  const issued = { ...config, issuerPath: 'https://auth.com' }
  const handoff = { state: 's', redirect_uri: 'https://app.com/cb' }
  const authorize = jest.fn().mockResolvedValue({ access_token: 'a' })

  it('accepts the issuer it asked', async () => {
    const result = await complete(issued, 'https://app.com/cb?code=c&state=s&iss=https%3A%2F%2Fauth.com', handoff, {
      functions: { authorize },
      verifyIdToken: claims({})
    })
    expect(result?.access_token).toBe('a')
  })

  it('refuses a code that came back from somewhere else, before exchanging it', async () => {
    const exchange = jest.fn()
    const result = await complete(issued, 'https://app.com/cb?code=c&state=s&iss=https%3A%2F%2Fevil.com', handoff, {
      functions: { authorize: exchange }
    })
    expect(result).toEqual({ error: 'Invalid issuer' })
    expect(exchange).not.toHaveBeenCalled()
  })

  it('tolerates a trailing slash and nothing more', async () => {
    const result = await complete(issued, 'https://app.com/cb?code=c&state=s&iss=https%3A%2F%2Fauth.com%2F', handoff, {
      functions: { authorize },
      verifyIdToken: claims({})
    })
    expect(result?.access_token).toBe('a')
  })

  it('lets a provider that never promised iss omit it', async () => {
    const result = await complete(issued, 'https://app.com/cb?code=c&state=s', handoff, {
      functions: { authorize },
      verifyIdToken: claims({})
    })
    expect(result?.access_token).toBe('a')
  })

  // A provider that advertises the parameter has promised to send it, so silence is a failure.
  it('refuses a missing iss from a provider that advertised it', async () => {
    const result = await complete({ ...issued, issuerParameter: true }, 'https://app.com/cb?code=c&state=s', handoff, {
      functions: { authorize }
    })
    expect(result).toEqual({ error: 'Missing issuer' })
  })

  it('still prefers reporting the provider’s own error over a missing iss', async () => {
    const result = await complete({ ...issued, issuerParameter: true }, 'https://app.com/cb?error=access_denied&state=s', handoff, {
      functions: { authorize: async token => token }
    })
    expect(result?.error).toBe('access_denied')
  })

  it('checks the implicit flow too', async () => {
    const result = await complete(issued, { hash: '#access_token=a&state=s&iss=https%3A%2F%2Fevil.com' }, handoff)
    expect(result).toEqual({ error: 'Invalid issuer' })
  })
})
