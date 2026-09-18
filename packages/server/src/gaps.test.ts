import { beforeEach, describe, expect, test } from 'bun:test'
import { compactDecrypt, createLocalJWKSet, decodeJwt, decodeProtectedHeader, exportJWK, generateKeyPair, jwtVerify } from 'jose'
import { memoryAdapter } from './adapters/memory'
import type { Adapter, Client, RequestContext } from './index'
import { certificateThumbprint } from './mtls'
import { createProvider, type Provider } from './provider'
import { base64url, sha256, token } from './random'
import { SESSION_COOKIE } from './session'
import { meetsRequirement } from './step-up'

const ISSUER = 'https://op.example.com'
const REDIRECT = 'https://rp.example.com/cb'
const SECRET = 'a-long-enough-client-secret'

const client = (over: Partial<Client> = {}): Client => ({
  clientId: 'rp',
  clientSecret: SECRET,
  redirectUris: [REDIRECT],
  grantTypes: ['authorization_code', 'refresh_token'],
  responseTypes: ['code'],
  scopes: ['openid', 'profile'],
  tokenEndpointAuthMethod: 'client_secret_basic',
  createdAt: new Date(),
  updatedAt: new Date(),
  ...over
})

const accounts = {
  async find(accountId: string) {
    return { accountId, claims: {} }
  },
  async claims() {
    return { name: 'Ada', email: 'ada@example.test' }
  }
}

let adapter: Adapter
let verifier: string
let challenge: string

const basic = (id = 'rp', secret = SECRET) => `Basic ${btoa(`${id}:${secret}`)}`

beforeEach(async () => {
  adapter = await memoryAdapter({ accounts })
  verifier = token(32) + token(32)
  challenge = base64url(await sha256(verifier))
})

const build = (over: Record<string, unknown> = {}) =>
  createProvider({ issuer: ISSUER, adapter, interactionUrl: `${ISSUER}/interaction`, ...over } as Parameters<typeof createProvider>[0])

const tokensFor = async (provider: Provider, clientId = 'rp', context?: Partial<RequestContext>) => {
  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: REDIRECT,
    response_type: 'code',
    scope: 'openid profile',
    code_challenge: challenge,
    code_challenge_method: 'S256'
  })
  let response = await provider.handle(new Request(`${ISSUER}/authorize?${params}`))
  let cookie = ''
  for (let leg = 0; leg < 4; leg++) {
    const location = new URL(response.headers.get('location') as string)
    if (!location.pathname.startsWith('/interaction/')) {
      const code = location.searchParams.get('code') as string
      return (
        await provider.handle(
          new Request(`${ISSUER}/token`, {
            method: 'POST',
            headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: basic(clientId) },
            body: new URLSearchParams({
              grant_type: 'authorization_code',
              code,
              redirect_uri: REDIRECT,
              code_verifier: verifier
            }).toString()
          }),
          context
        )
      ).json()
    }
    const id = location.pathname.split('/').pop() as string
    const view = await provider.interactions.find(id)
    const done = await provider.interactions.complete(
      id,
      view.kind === 'login' ? { login: { accountId: 'ada', acr: 'pwd' } } : { consent: { scopes: view.scopes } }
    )
    if (done.setCookie) cookie = `${SESSION_COOKIE}=${done.setCookie.split('=')[1]?.split(';')[0]}`
    response = await provider.handle(new Request(done.redirectTo, { headers: cookie ? { cookie } : {} }))
  }
  throw new Error('never reached the redirect')
}

describe('FR-T2: JWT access tokens', () => {
  test('opaque by default', async () => {
    await adapter.clients.create?.(client())
    const issued = await tokensFor(build())
    expect(issued.access_token.split('.')).toHaveLength(1)
  })

  test('a client can opt into RFC 9068 format', async () => {
    await adapter.clients.create?.(client({ accessTokenFormat: 'jwt' }))
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
    await adapter.clients.create?.(client({ accessTokenFormat: 'jwt' }))
    const provider = build()
    const issued = await tokensFor(provider)

    const before = await provider.handle(new Request(`${ISSUER}/userinfo`, { headers: { authorization: `Bearer ${issued.access_token}` } }))
    expect(before.status).toBe(200)

    await provider.handle(
      new Request(`${ISSUER}/token`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: basic() },
        body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: 'x' }).toString()
      })
    )
    const jti = decodeJwt(issued.access_token).jti as string
    await adapter.artifacts.destroy('access_token', jti)

    const after = await provider.handle(new Request(`${ISSUER}/userinfo`, { headers: { authorization: `Bearer ${issued.access_token}` } }))
    expect(after.status).toBe(401)
  })

  test('a JWT this provider did not issue is not accepted', async () => {
    await adapter.clients.create?.(client())
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

describe('FR-C5: signed and encrypted UserInfo', () => {
  test('a signed response is a JWT the client can verify', async () => {
    await adapter.clients.create?.(client({ userinfoSignedResponseAlg: 'ES256' }))
    const provider = build()
    const issued = await tokensFor(provider)

    const response = await provider.handle(
      new Request(`${ISSUER}/userinfo`, { headers: { authorization: `Bearer ${issued.access_token}` } })
    )
    expect(response.headers.get('content-type')).toContain('application/jwt')

    const jwks = await (await provider.handle(new Request(`${ISSUER}/jwks`))).json()
    const { payload } = await jwtVerify(await response.text(), createLocalJWKSet(jwks), { issuer: ISSUER, audience: 'rp' })
    expect(payload.sub).toBe('ada')
    expect(payload.name).toBe('Ada')
  })

  test('an encrypted response is a JWE the client can decrypt', async () => {
    const encryption = await generateKeyPair('RSA-OAEP-256', { extractable: true })
    const publicJwk = { ...(await exportJWK(encryption.publicKey)), use: 'enc', alg: 'RSA-OAEP-256' }
    await adapter.clients.create?.(
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
    expect(decodeJwt(inner).name).toBe('Ada')
  })

  test('plain JSON when the client asked for neither', async () => {
    await adapter.clients.create?.(client())
    const provider = build()
    const issued = await tokensFor(provider)
    const response = await provider.handle(
      new Request(`${ISSUER}/userinfo`, { headers: { authorization: `Bearer ${issued.access_token}` } })
    )
    expect(response.headers.get('content-type')).toContain('application/json')
  })
})

describe('FR-C11: front-channel logout', () => {
  test('yields the iframe URLs rather than rendering them', async () => {
    let targets: { clientId: string; uri: string }[] = []
    await adapter.clients.create?.(client({ frontchannelLogoutUri: 'https://rp.example.com/fc' }))
    const provider = build({
      onFrontChannelLogout: (received: { clientId: string; uri: string }[]) => {
        targets = received
      }
    })
    const issued = await tokensFor(provider)
    const session = (await adapter.sessions.findByAccount('ada'))[0]

    await provider.handle(new Request(`${ISSUER}/session/end`, { headers: { cookie: `${SESSION_COOKIE}=${session?.id}` } }))
    expect(targets).toEqual([{ clientId: 'rp', uri: 'https://rp.example.com/fc' }])
    expect(issued.access_token).toBeTruthy()
  })

  // §2 makes iss/sid opt-in: sending a session id to a client that never asked leaks it for nothing.
  test('iss and sid go only to a client that asked for them', async () => {
    let targets: { clientId: string; uri: string }[] = []
    await adapter.clients.create?.(client({ frontchannelLogoutUri: 'https://rp.example.com/fc', frontchannelLogoutSessionRequired: true }))
    const provider = build({
      onFrontChannelLogout: (received: { clientId: string; uri: string }[]) => {
        targets = received
      }
    })
    await tokensFor(provider)
    const session = (await adapter.sessions.findByAccount('ada'))[0]
    await provider.handle(new Request(`${ISSUER}/session/end`, { headers: { cookie: `${SESSION_COOKIE}=${session?.id}` } }))

    const url = new URL(targets[0]?.uri as string)
    expect(url.searchParams.get('iss')).toBe(ISSUER)
    expect(url.searchParams.get('sid')).toBe(session?.id ?? null)
  })

  test('a client with no front-channel URI is not contacted', async () => {
    let targets: unknown[] = []
    await adapter.clients.create?.(client())
    const provider = build({
      onFrontChannelLogout: (received: unknown[]) => {
        targets = received
      }
    })
    await tokensFor(provider)
    const session = (await adapter.sessions.findByAccount('ada'))[0]
    await provider.handle(new Request(`${ISSUER}/session/end`, { headers: { cookie: `${SESSION_COOKIE}=${session?.id}` } }))
    expect(targets).toEqual([])
  })
})

describe('FR-C4 and FR-C13: mTLS', () => {
  const DER = new Uint8Array([0x30, 0x82, 0x01, 0x0a, 0x02, 0x01, 0x05])
  const certificate = { der: DER, subjectDn: 'CN=rp,O=Example' }

  const mtlsProvider = () =>
    build({ capabilities: { clientCertificate: true }, clientAuthMethods: ['tls_client_auth', 'self_signed_tls_client_auth', 'none'] })

  test('tls_client_auth authenticates by the registered subject DN', async () => {
    await adapter.clients.create?.(client({ tokenEndpointAuthMethod: 'tls_client_auth', tlsClientAuthSubjectDn: 'CN=rp,O=Example' }))
    const provider = mtlsProvider()
    const response = await provider.handle(
      new Request(`${ISSUER}/token`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'authorization_code', client_id: 'rp', code: 'x', redirect_uri: REDIRECT }).toString()
      }),
      { clientCertificate: certificate }
    )
    // Past authentication: the failure is now the bogus code, not the client.
    expect((await response.json()).error).toBe('invalid_grant')
  })

  test('a different subject DN is refused', async () => {
    await adapter.clients.create?.(client({ tokenEndpointAuthMethod: 'tls_client_auth', tlsClientAuthSubjectDn: 'CN=someone-else' }))
    const provider = mtlsProvider()
    const response = await provider.handle(
      new Request(`${ISSUER}/token`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'authorization_code', client_id: 'rp', code: 'x' }).toString()
      }),
      { clientCertificate: certificate }
    )
    expect((await response.json()).error).toBe('invalid_client')
  })

  test('no certificate at all is refused', async () => {
    await adapter.clients.create?.(client({ tokenEndpointAuthMethod: 'tls_client_auth', tlsClientAuthSubjectDn: 'CN=rp,O=Example' }))
    const provider = mtlsProvider()
    const response = await provider.handle(
      new Request(`${ISSUER}/token`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'authorization_code', client_id: 'rp', code: 'x' }).toString()
      })
    )
    expect((await response.json()).error_description).toContain('no client certificate was presented')
  })

  test('self_signed_tls_client_auth matches the registered thumbprint', async () => {
    const thumbprint = await certificateThumbprint(DER)
    await adapter.clients.create?.(
      client({ tokenEndpointAuthMethod: 'self_signed_tls_client_auth', jwks: { keys: [{ 'x5t#S256': thumbprint }] } })
    )
    const provider = mtlsProvider()
    const response = await provider.handle(
      new Request(`${ISSUER}/token`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'authorization_code', client_id: 'rp', code: 'x' }).toString()
      }),
      { clientCertificate: certificate }
    )
    expect((await response.json()).error).toBe('invalid_grant')
  })

  // FR-R5 / G-8: a runtime that cannot supply a certificate must not advertise these.
  test('the methods are absent from discovery where no certificate can arrive', async () => {
    await adapter.clients.create?.(client())
    const metadata = await (await build().handle(new Request(`${ISSUER}/.well-known/openid-configuration`))).json()
    expect(metadata.token_endpoint_auth_methods_supported).not.toContain('tls_client_auth')
    expect(metadata).not.toHaveProperty('tls_client_certificate_bound_access_tokens')

    const capable = await (await mtlsProvider().handle(new Request(`${ISSUER}/.well-known/openid-configuration`))).json()
    expect(capable.tls_client_certificate_bound_access_tokens).toBe(true)
  })

  test('a certificate-bound token is refused without the certificate', async () => {
    await adapter.clients.create?.(client({ certificateBoundAccessTokens: true }))
    const provider = build({ capabilities: { clientCertificate: true } })
    const issued = await tokensFor(provider, 'rp', { clientCertificate: certificate })
    const stored = await adapter.artifacts.find('access_token', issued.access_token)
    expect((stored?.payload.cnf as { 'x5t#S256'?: string } | undefined)?.['x5t#S256']).toBe(await certificateThumbprint(DER))

    const without = await provider.handle(
      new Request(`${ISSUER}/userinfo`, { headers: { authorization: `Bearer ${issued.access_token}` } })
    )
    expect(without.status).toBe(401)

    const with_ = await provider.handle(
      new Request(`${ISSUER}/userinfo`, { headers: { authorization: `Bearer ${issued.access_token}` } }),
      { clientCertificate: certificate }
    )
    expect(with_.status).toBe(200)
  })
})

describe('FR-C16: the resource-server challenge', () => {
  // 403 with no challenge tells a client it failed but not what would succeed.
  test('an unmet acr produces a challenge naming what is required', () => {
    const verdict = meetsRequirement({ acrValues: ['mfa'] }, { acr: 'pwd', authTime: new Date() })
    expect(verdict.sufficient).toBe(false)
    if (!verdict.sufficient) {
      expect(verdict.challenge).toContain('insufficient_user_authentication')
      expect(verdict.challenge).toContain('acr_values="mfa"')
    }
  })

  test('a met acr is sufficient', () => {
    expect(meetsRequirement({ acrValues: ['mfa'] }, { acr: 'mfa', authTime: new Date() }).sufficient).toBe(true)
  })

  test('a stale authentication produces a max_age challenge', () => {
    const verdict = meetsRequirement({ maxAge: 60 }, { acr: 'pwd', authTime: new Date(Date.now() - 600_000) })
    expect(verdict.sufficient).toBe(false)
    if (!verdict.sufficient) expect(verdict.challenge).toContain('max_age="60"')
  })

  test('a fresh authentication is sufficient', () => {
    expect(meetsRequirement({ maxAge: 600 }, { acr: 'pwd', authTime: new Date() }).sufficient).toBe(true)
  })

  test('no requirement at all is sufficient', () => {
    expect(meetsRequirement({}, {}).sufficient).toBe(true)
  })

  test('an unknown authentication time fails a max_age requirement', () => {
    expect(meetsRequirement({ maxAge: 60 }, {}).sufficient).toBe(false)
  })
})
