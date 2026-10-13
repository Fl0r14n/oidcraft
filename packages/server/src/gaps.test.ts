import { beforeEach, describe, expect, setSystemTime, test } from 'bun:test'
import { randomString, sha256 } from '@oidcraft/core'
import { base64url, compactDecrypt, createLocalJWKSet, decodeJwt, decodeProtectedHeader, exportJWK, generateKeyPair, jwtVerify } from 'jose'
import { memoryAdapter } from './adapters/memory'
import { certificateThumbprint } from './binding/mtls'
import type { Adapter, Client, RequestContext } from './index'
import { createProvider, type Provider } from './provider'
import { meetsRequirement } from './resource/step-up'
import { SESSION_COOKIE } from './session/session'

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
  verifier = randomString() + randomString()
  challenge = base64url.encode(await sha256(verifier))
})

const build = (over: Record<string, unknown> = {}) =>
  createProvider({ issuer: ISSUER, adapter, interactionUrl: `${ISSUER}/interaction`, ...over } as Parameters<typeof createProvider>[0])

const tokensFor = async (
  provider: Provider,
  clientId = 'rp',
  context?: Partial<RequestContext>,
  { session, scope = 'openid profile' }: { session?: string | undefined; scope?: string } = {}
) => {
  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: REDIRECT,
    response_type: 'code',
    scope,
    code_challenge: challenge,
    code_challenge_method: 'S256'
  })
  let cookie = session ? `${SESSION_COOKIE}=${session}` : ''
  let response = await provider.handle(new Request(`${ISSUER}/authorize?${params}`, { headers: cookie ? { cookie } : {} }))
  for (let leg = 0; leg < 4; leg++) {
    const location = new URL(response.headers.get('location') as string)
    if (!location.pathname.startsWith('/interaction/')) {
      const code = location.searchParams.get('code') as string
      const isPublic = (await adapter.clients.find(clientId))?.tokenEndpointAuthMethod === 'none'
      return (
        await provider.handle(
          new Request(`${ISSUER}/token`, {
            method: 'POST',
            headers: { 'content-type': 'application/x-www-form-urlencoded', ...(!isPublic && { authorization: basic(clientId) }) },
            body: new URLSearchParams({
              grant_type: 'authorization_code',
              ...(isPublic && { client_id: clientId }),
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

/** RP-initiated logout as a relying party sends it: with the ID token it was issued (OIDC RP-Initiated Logout 1.0 §2). */
const endSession = (provider: Provider, sessionId: string | undefined, idToken: string) =>
  provider.handle(
    new Request(`${ISSUER}/session/end?${new URLSearchParams({ id_token_hint: idToken })}`, {
      headers: { cookie: `${SESSION_COOKIE}=${sessionId}` }
    })
  )

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
    expect(await adapter.artifacts.find('access_token', decodeJwt(issued.access_token).jti as string)).toBeUndefined()

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
    await adapter.artifacts.destroy('access_token', decodeJwt(issued.access_token).jti as string)
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
    expect(payload.name).toBe('Ada')
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
    expect(decodeJwt(inner).name).toBe('Ada')
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

describe('FR-C11: front-channel logout', () => {
  test('yields the iframe URLs rather than rendering them', async () => {
    let targets: { clientId: string; uri: string }[] = []
    await adapter.clients.upsert?.(client({ frontchannelLogoutUri: 'https://rp.example.com/fc' }))
    const provider = build({
      onFrontChannelLogout: (received: { clientId: string; uri: string }[]) => {
        targets = received
      }
    })
    const issued = await tokensFor(provider)
    const session = (await adapter.sessions.listForAccount('ada'))[0]

    await endSession(provider, session?.id, issued.id_token)
    expect(targets).toEqual([{ clientId: 'rp', uri: 'https://rp.example.com/fc' }])
    expect(issued.access_token).toBeTruthy()
  })

  // §2 makes iss/sid opt-in: sending a session id to a client that never asked leaks it for nothing.
  test('iss and sid go only to a client that asked for them', async () => {
    let targets: { clientId: string; uri: string }[] = []
    await adapter.clients.upsert?.(client({ frontchannelLogoutUri: 'https://rp.example.com/fc', frontchannelLogoutSessionRequired: true }))
    const provider = build({
      onFrontChannelLogout: (received: { clientId: string; uri: string }[]) => {
        targets = received
      }
    })
    const issued = await tokensFor(provider)
    const session = (await adapter.sessions.listForAccount('ada'))[0]
    await endSession(provider, session?.id, issued.id_token)

    const url = new URL(targets[0]?.uri as string)
    expect(url.searchParams.get('iss')).toBe(ISSUER)
    expect(url.searchParams.get('sid')).toBe(session?.id ?? null)
  })

  test('every client the session signed in to is notified, not only the first', async () => {
    let targets: { clientId: string; uri: string }[] = []
    await adapter.clients.upsert?.(client({ frontchannelLogoutUri: 'https://rp.example.com/fc' }))
    await adapter.clients.upsert?.(client({ clientId: 'rp2', frontchannelLogoutUri: 'https://rp2.example.com/fc' }))
    const provider = build({
      onFrontChannelLogout: (received: { clientId: string; uri: string }[]) => {
        targets = received
      }
    })
    const issued = await tokensFor(provider)
    const session = (await adapter.sessions.listForAccount('ada'))[0]
    await tokensFor(provider, 'rp2', undefined, { session: session?.id })
    expect(await adapter.sessions.listForAccount('ada')).toHaveLength(1)

    await endSession(provider, session?.id, issued.id_token)
    expect(targets.map(target => target.clientId).sort()).toEqual(['rp', 'rp2'])
  })

  test('a client with no front-channel URI is not contacted', async () => {
    let targets: unknown[] = []
    await adapter.clients.upsert?.(client())
    const provider = build({
      onFrontChannelLogout: (received: unknown[]) => {
        targets = received
      }
    })
    const issued = await tokensFor(provider)
    const session = (await adapter.sessions.listForAccount('ada'))[0]
    await endSession(provider, session?.id, issued.id_token)
    expect(targets).toEqual([])
  })
})

const DER = new Uint8Array([0x30, 0x82, 0x01, 0x0a, 0x02, 0x01, 0x05])
const certificate = { thumbprint: await certificateThumbprint(DER), subjectDn: 'CN=rp,O=Example' }

describe('FR-C4 and FR-C13: mTLS', () => {
  const mtlsProvider = () =>
    build({ capabilities: { clientCertificate: true }, clientAuthMethods: ['tls_client_auth', 'self_signed_tls_client_auth', 'none'] })

  test('tls_client_auth authenticates by the registered subject DN', async () => {
    await adapter.clients.upsert?.(client({ tokenEndpointAuthMethod: 'tls_client_auth', tlsClientAuthSubjectDn: 'CN=rp,O=Example' }))
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
    await adapter.clients.upsert?.(client({ tokenEndpointAuthMethod: 'tls_client_auth', tlsClientAuthSubjectDn: 'CN=someone-else' }))
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
    await adapter.clients.upsert?.(client({ tokenEndpointAuthMethod: 'tls_client_auth', tlsClientAuthSubjectDn: 'CN=rp,O=Example' }))
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
    await adapter.clients.upsert?.(
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
    await adapter.clients.upsert?.(client())
    const metadata = await (await build().handle(new Request(`${ISSUER}/.well-known/openid-configuration`))).json()
    expect(metadata.token_endpoint_auth_methods_supported).not.toContain('tls_client_auth')
    expect(metadata).not.toHaveProperty('tls_client_certificate_bound_access_tokens')

    const capable = await (await mtlsProvider().handle(new Request(`${ISSUER}/.well-known/openid-configuration`))).json()
    expect(capable.tls_client_certificate_bound_access_tokens).toBe(true)
  })

  test('a certificate-bound token is refused without the certificate', async () => {
    await adapter.clients.upsert?.(client({ certificateBoundAccessTokens: true }))
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

  const form = (path: string, body: Record<string, string>, authorization?: string) =>
    new Request(`${ISSUER}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', ...(authorization && { authorization }) },
      body: new URLSearchParams(body).toString()
    })

  // FR-C4: a client whose only credential is its certificate must be able to use every endpoint that authenticates it.
  test('tls_client_auth works at revocation and introspection, not only the token endpoint', async () => {
    await adapter.clients.upsert?.(client({ tokenEndpointAuthMethod: 'tls_client_auth', tlsClientAuthSubjectDn: 'CN=rp,O=Example' }))
    const provider = mtlsProvider()
    const introspected = await provider.handle(form('/introspect', { client_id: 'rp', token: 'nope' }), { clientCertificate: certificate })
    expect(await introspected.json()).toEqual({ active: false })
    const revoked = await provider.handle(form('/revoke', { client_id: 'rp', token: 'nope' }), { clientCertificate: certificate })
    expect(revoked.status).toBe(200)
    expect((await provider.handle(form('/revoke', { client_id: 'rp', token: 'nope' }))).status).toBe(401)
  })

  // RFC 8705 §3: the binding is not a property of the first access token only.
  test('a refreshed access token stays bound to the certificate', async () => {
    await adapter.clients.upsert?.(client({ certificateBoundAccessTokens: true, scopes: ['openid', 'profile', 'offline_access'] }))
    const provider = build({ capabilities: { clientCertificate: true } })
    const issued = await tokensFor(provider, 'rp', { clientCertificate: certificate }, { scope: 'openid offline_access' })
    expect(issued.refresh_token).toBeTruthy()

    const refreshed = await (
      await provider.handle(form('/token', { grant_type: 'refresh_token', refresh_token: issued.refresh_token }, basic()), {
        clientCertificate: certificate
      })
    ).json()
    const stored = await adapter.artifacts.find('access_token', refreshed.access_token)
    expect((stored?.payload.cnf as { 'x5t#S256'?: string } | undefined)?.['x5t#S256']).toBe(certificate.thumbprint)
  })

  // RFC 8705 §4: a public client has no other credential, so its refresh token is held to the certificate.
  test("a public client's refresh token needs the same certificate", async () => {
    await adapter.clients.upsert?.(
      client({ tokenEndpointAuthMethod: 'none', certificateBoundAccessTokens: true, scopes: ['openid', 'profile', 'offline_access'] })
    )
    const provider = mtlsProvider()
    const issued = await tokensFor(provider, 'rp', { clientCertificate: certificate }, { scope: 'openid offline_access' })
    const refresh = (clientCertificate: typeof certificate) =>
      provider.handle(form('/token', { grant_type: 'refresh_token', client_id: 'rp', refresh_token: issued.refresh_token }), {
        clientCertificate
      })

    const other = await refresh({ ...certificate, thumbprint: 'someone-elses' })
    expect((await other.json()).error_description).toContain('different certificate')
    expect((await refresh(certificate)).status).toBe(200)
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
    const session = (await adapter.sessions.listForAccount('ada'))[0]
    await endSession(provider, session?.id, issued.id_token)
    expect(decodeJwt(tokens[0]?.logoutToken as string).sub).toBe(decodeJwt(issued.id_token).sub as string)
  })
})

describe('an issuer with a path', () => {
  const PATHED = 'https://op.example.com/auth'

  test('serves every route under that path, as discovery publishes them', async () => {
    await adapter.clients.upsert?.(client())
    const provider = createProvider({ issuer: PATHED, adapter, interactionUrl: `${PATHED}/interaction` })
    const discovery = await provider.handle(new Request(`${PATHED}/.well-known/openid-configuration`))
    expect(discovery.status).toBe(200)
    const metadata = await discovery.json()
    expect(metadata.token_endpoint).toBe(`${PATHED}/token`)
    expect((await provider.handle(new Request(`${PATHED}/jwks`))).status).toBe(200)
    // A host that mounted the provider under the prefix and stripped it is served too.
    expect((await provider.handle(new Request('https://op.example.com/jwks'))).status).toBe(200)
  })

  test('a trailing slash on a pathed issuer changes nothing', async () => {
    const provider = createProvider({ issuer: `${PATHED}/`, adapter, interactionUrl: `${PATHED}/interaction` })
    const metadata = await (await provider.handle(new Request(`${PATHED}/.well-known/openid-configuration`))).json()
    expect(metadata.issuer).toBe(PATHED)
    expect(metadata.token_endpoint).toBe(`${PATHED}/token`)
  })
})

describe('CORS', () => {
  const RP = 'https://rp.example.com'
  const token = (provider: Provider, origin: string, authorization = basic()) =>
    provider.handle(
      new Request(`${ISSUER}/token`, {
        method: 'POST',
        headers: { origin, authorization, 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'authorization_code', code: 'x', redirect_uri: REDIRECT }).toString()
      })
    )

  test('discovery and the key set are readable from any origin', async () => {
    const provider = build()
    for (const path of ['/.well-known/openid-configuration', '/jwks']) {
      const response = await provider.handle(new Request(`${ISSUER}${path}`, { headers: { origin: 'https://anywhere.example' } }))
      expect(response.headers.get('access-control-allow-origin')).toBe('*')
    }
  })

  test('a preflight on a client endpoint names the methods and the headers a browser client sends', async () => {
    const response = await build().handle(
      new Request(`${ISSUER}/token`, { method: 'OPTIONS', headers: { origin: RP, 'access-control-request-method': 'POST' } })
    )
    expect(response.status).toBe(204)
    expect(response.headers.get('access-control-allow-origin')).toBe(RP)
    expect(response.headers.get('access-control-allow-headers')).toContain('dpop')
  })

  // The registration already says where the client lives; nothing else is configured.
  test("a response is readable only on the origin of the calling client's redirect URIs", async () => {
    await adapter.clients.upsert?.(client())
    const provider = build()
    const mine = await token(provider, RP)
    expect(mine.status).toBe(400)
    expect(mine.headers.get('access-control-allow-origin')).toBe(RP)
    expect(mine.headers.get('access-control-expose-headers')).toContain('dpop-nonce')

    const theirs = await token(provider, 'https://evil.example')
    expect(theirs.headers.get('access-control-allow-origin')).toBeNull()
    expect(theirs.headers.get('vary')).toContain('origin')
  })

  test('UserInfo identifies the client by its access token', async () => {
    await adapter.clients.upsert?.(client())
    const provider = build()
    const issued = await tokensFor(provider)
    const response = await provider.handle(
      new Request(`${ISSUER}/userinfo`, { headers: { origin: RP, authorization: `Bearer ${issued.access_token}` } })
    )
    expect(response.status).toBe(200)
    expect(response.headers.get('access-control-allow-origin')).toBe(RP)
  })
})

describe('FR-C8: introspection by a resource server', () => {
  const introspect = async (provider: Provider, token: string, as: string) =>
    (
      await provider.handle(
        new Request(`${ISSUER}/introspect`, {
          method: 'POST',
          headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: basic(as) },
          body: new URLSearchParams({ token }).toString()
        })
      )
    ).json()

  test('a resource server may introspect access tokens issued to other clients; another client may not', async () => {
    await adapter.clients.upsert?.(client({ scopes: ['openid', 'profile', 'offline_access'] }))
    await adapter.clients.upsert?.(client({ clientId: 'api', resourceServer: true }))
    await adapter.clients.upsert?.(client({ clientId: 'other' }))
    const provider = build()
    const issued = await tokensFor(provider, 'rp', undefined, { scope: 'openid offline_access' })

    expect(await introspect(provider, issued.access_token, 'api')).toMatchObject({ active: true, client_id: 'rp', sub: 'ada' })
    expect(await introspect(provider, issued.access_token, 'other')).toEqual({ active: false })
    // A refresh token is never presented to a resource server.
    expect(await introspect(provider, issued.refresh_token, 'api')).toEqual({ active: false })
  })

  test('a token restricted to another audience is inactive to this resource server', async () => {
    await adapter.clients.upsert?.(client())
    await adapter.clients.upsert?.(client({ clientId: 'api', resourceServer: true }))
    const provider = build()
    const issued = await tokensFor(provider)
    const stored = await adapter.artifacts.find('access_token', issued.access_token)
    await adapter.artifacts.upsert({ ...(stored as NonNullable<typeof stored>), payload: { ...stored?.payload, aud: 'billing' } })
    expect(await introspect(provider, issued.access_token, 'api')).toEqual({ active: false })
  })

  test('iat is when the token was issued, not when it expires', async () => {
    await adapter.clients.upsert?.(client())
    const provider = build()
    const before = Math.floor(Date.now() / 1000)
    const issued = await tokensFor(provider)
    const body = await introspect(provider, issued.access_token, 'rp')
    expect(body.iat).toBeGreaterThanOrEqual(before)
    expect(body.iat).toBeLessThan(body.exp)
  })
})

describe('malformed credentials are client errors, not 500s', () => {
  test('a Basic header that is not base64, or not percent-decodable, is invalid_client', async () => {
    await adapter.clients.upsert?.(client())
    const provider = build()
    for (const authorization of ['Basic !!!not-base64!!!', `Basic ${btoa('rp:%E0%A4%A')}`]) {
      const response = await provider.handle(
        new Request(`${ISSUER}/token`, {
          method: 'POST',
          headers: { authorization, 'content-type': 'application/x-www-form-urlencoded' },
          body: 'grant_type=authorization_code&code=x'
        })
      )
      expect({ authorization, status: response.status }).toEqual({ authorization, status: 401 })
    }
  })

  test('a cookie that is not percent-decodable is ignored', async () => {
    await adapter.clients.upsert?.(client())
    const params = new URLSearchParams({
      client_id: 'rp',
      redirect_uri: REDIRECT,
      response_type: 'code',
      scope: 'openid',
      code_challenge: challenge,
      code_challenge_method: 'S256'
    })
    const response = await build().handle(
      new Request(`${ISSUER}/authorize?${params}`, { headers: { cookie: `${SESSION_COOKIE}=%E0%A4%A; other=1` } })
    )
    expect(response.status).toBe(303)
  })
})

describe('ID token details', () => {
  // OIDC Core §3.3.2.11: the hash is the signing algorithm's, so an ES384 token halves a SHA-384.
  test('at_hash uses the hash of the signing algorithm, and the token names its sid', async () => {
    const pair = await generateKeyPair('ES384', { extractable: true })
    const key = { kid: 'es384', alg: 'ES384' }
    const active = adapter.keys.active.bind(adapter.keys)
    adapter.keys.active = async () => [
      {
        ...key,
        privateJwk: { ...(await exportJWK(pair.privateKey)), ...key },
        publicJwk: { ...(await exportJWK(pair.publicKey)), ...key }
      },
      ...(await active())
    ]
    await adapter.clients.upsert?.(client({ idTokenSignedResponseAlg: 'ES384' }))
    const issued = await tokensFor(build())
    const claims = decodeJwt(issued.id_token)
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-384', new TextEncoder().encode(issued.access_token)))
    expect(decodeProtectedHeader(issued.id_token).alg).toBe('ES384')
    expect(claims.at_hash).toBe(base64url.encode(digest.slice(0, 24)))
    expect(claims.sid).toBe((await adapter.sessions.listForAccount('ada'))[0]?.id)
  })

  test('a refresh narrowed to exclude openid returns no ID token', async () => {
    await adapter.clients.upsert?.(client({ scopes: ['openid', 'profile', 'offline_access'] }))
    const provider = build()
    const issued = await tokensFor(provider, 'rp', undefined, { scope: 'openid profile offline_access' })
    const refreshed = await (
      await provider.handle(
        new Request(`${ISSUER}/token`, {
          method: 'POST',
          headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: basic() },
          body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: issued.refresh_token, scope: 'profile' }).toString()
        })
      )
    ).json()
    expect(refreshed.access_token).toBeTruthy()
    expect(refreshed.id_token).toBeUndefined()
  })
})

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

describe('discovery advertises what verification accepts', () => {
  test('client-side algorithm lists are what clients may sign with, not what the provider signs with', async () => {
    const provider = build({
      clientAuthMethods: ['client_secret_basic', 'private_key_jwt', 'client_secret_jwt'],
      features: { dpop: true }
    })
    const metadata = await (await provider.handle(new Request(`${ISSUER}/.well-known/openid-configuration`))).json()
    expect(metadata.token_endpoint_auth_signing_alg_values_supported).toEqual(expect.arrayContaining(['PS384', 'EdDSA', 'HS256']))
    expect(metadata.dpop_signing_alg_values_supported).toContain('ES384')
    expect(metadata.request_object_signing_alg_values_supported).toEqual(expect.arrayContaining(['RS512', 'EdDSA']))
    expect(metadata.request_object_signing_alg_values_supported).not.toContain('HS256')
  })

  test('without a JWT client authentication method there is no assertion algorithm list', async () => {
    const provider = build({ clientAuthMethods: ['client_secret_basic', 'none'] })
    const metadata = await (await provider.handle(new Request(`${ISSUER}/.well-known/openid-configuration`))).json()
    expect(metadata).not.toHaveProperty('token_endpoint_auth_signing_alg_values_supported')
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
    expect(await adapter.artifacts.find('access_token', decodeJwt(body.access_token).jti as string)).toBeTruthy()
  })
})
