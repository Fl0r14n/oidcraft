import { beforeEach, describe, expect, test } from 'bun:test'
import { exportJWK, generateKeyPair, SignJWT } from 'jose'
import { memoryAdapter } from './adapters/memory'
import { accessTokenHash } from './dpop'
import type { Adapter, Client } from './index'
import { createProvider, type Provider } from './provider'
import { base64url, sha256, token } from './random'
import { SESSION_COOKIE } from './session'

const ISSUER = 'https://op.example.com'
const REDIRECT = 'https://rp.example.com/cb'

const client = (over: Partial<Client> = {}): Client => ({
  clientId: 'rp',
  redirectUris: [REDIRECT],
  grantTypes: ['authorization_code', 'refresh_token'],
  responseTypes: ['code'],
  scopes: ['openid', 'offline_access'],
  tokenEndpointAuthMethod: 'none',
  createdAt: new Date(),
  updatedAt: new Date(),
  ...over
})

const accounts = {
  async find(accountId: string) {
    return { accountId, claims: {} }
  },
  async claims() {
    return { name: 'Ada' }
  }
}

let adapter: Adapter
let provider: Provider
let verifier: string
let challenge: string
let keyPair: { privateKey: CryptoKey; publicKey: CryptoKey }

beforeEach(async () => {
  adapter = await memoryAdapter({ accounts })
  await adapter.clients.create?.(client())
  await adapter.clients.create?.(client({ clientId: 'strict', dpopBoundAccessTokens: true }))
  provider = createProvider({ issuer: ISSUER, adapter, interactionUrl: `${ISSUER}/interaction`, features: { dpop: true } })
  verifier = token(32) + token(32)
  challenge = base64url(await sha256(verifier))
  keyPair = await generateKeyPair('ES256', { extractable: true })
})

/** A DPoP proof as a client would build it (RFC 9449 §4.2). */
const proof = async (
  method: string,
  uri: string,
  over: { accessToken?: string; jti?: string; iat?: number; typ?: string; key?: typeof keyPair } = {}
) => {
  const key = over.key ?? keyPair
  const jwk = await exportJWK(key.publicKey)
  const builder = new SignJWT({
    jti: over.jti ?? token(16),
    htm: method,
    htu: uri,
    ...(over.accessToken && { ath: await accessTokenHash(over.accessToken) })
  })
    .setProtectedHeader({ alg: 'ES256', typ: over.typ ?? 'dpop+jwt', jwk })
    .setIssuedAt(over.iat ?? Math.floor(Date.now() / 1000))
  return builder.sign(key.privateKey)
}

const codeFor = async (clientId = 'rp') => {
  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: REDIRECT,
    response_type: 'code',
    scope: 'openid offline_access',
    code_challenge: challenge,
    code_challenge_method: 'S256'
  })
  let response = await provider.handle(new Request(`${ISSUER}/authorize?${params}`))
  let cookie = ''
  for (let i = 0; i < 3; i++) {
    const location = new URL(response.headers.get('location') as string)
    if (!location.pathname.startsWith('/interaction/')) return location.searchParams.get('code') as string
    const id = location.pathname.split('/').pop() as string
    const view = await provider.interactions.find(id)
    const done = await provider.interactions.complete(
      id,
      view.kind === 'login' ? { login: { accountId: 'ada' } } : { consent: { scopes: view.scopes } }
    )
    if (done.setCookie) cookie = `${SESSION_COOKIE}=${done.setCookie.split('=')[1]?.split(';')[0]}`
    response = await provider.handle(new Request(done.redirectTo, { headers: cookie ? { cookie } : {} }))
  }
  throw new Error('never reached the redirect')
}

const exchange = async (code: string, headers: Record<string, string> = {}, clientId = 'rp') =>
  provider.handle(
    new Request(`${ISSUER}/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: REDIRECT,
        code_verifier: verifier,
        client_id: clientId
      }).toString()
    })
  )

describe('DPoP binding', () => {
  test('a proof at the token endpoint yields a DPoP-bound token', async () => {
    const response = await exchange(await codeFor(), { dpop: await proof('POST', `${ISSUER}/token`) })
    expect(response.status).toBe(200)
    const body = await response.json()
    expect(body.token_type).toBe('DPoP')
  })

  test('without a proof the token is an ordinary Bearer', async () => {
    const body = await (await exchange(await codeFor())).json()
    expect(body.token_type).toBe('Bearer')
  })

  test('a client registered for bound tokens must present a proof', async () => {
    const response = await exchange(await codeFor('strict'), {}, 'strict')
    expect((await response.json()).error).toBe('invalid_dpop_proof')
  })

  test('introspection reports the binding so a resource server can enforce it', async () => {
    const tokens = await (await exchange(await codeFor(), { dpop: await proof('POST', `${ISSUER}/token`) })).json()
    await adapter.clients.update?.('rp', { tokenEndpointAuthMethod: 'none' })
    const artifact = await adapter.artifacts.find('access_token', tokens.access_token)
    expect(artifact?.payload.cnf).toHaveProperty('jkt')
  })
})

describe('DPoP at the resource', () => {
  const bound = async () => {
    const tokens = await (await exchange(await codeFor(), { dpop: await proof('POST', `${ISSUER}/token`) })).json()
    return tokens
  }

  test('a bound token works when presented with a matching proof', async () => {
    const tokens = await bound()
    const response = await provider.handle(
      new Request(`${ISSUER}/userinfo`, {
        headers: {
          authorization: `DPoP ${tokens.access_token}`,
          dpop: await proof('GET', `${ISSUER}/userinfo`, { accessToken: tokens.access_token })
        }
      })
    )
    expect(response.status).toBe(200)
    expect((await response.json()).sub).toBe('ada')
  })

  // RFC 9449 §7.1: this is the theft the whole mechanism exists to stop.
  test('a bound token presented as a Bearer is refused', async () => {
    const tokens = await bound()
    const response = await provider.handle(
      new Request(`${ISSUER}/userinfo`, { headers: { authorization: `Bearer ${tokens.access_token}` } })
    )
    expect(response.status).toBe(401)
    expect(response.headers.get('www-authenticate')).toContain('DPoP')
  })

  test("a bound token presented with someone else's key is refused", async () => {
    const tokens = await bound()
    const thief = await generateKeyPair('ES256', { extractable: true })
    const response = await provider.handle(
      new Request(`${ISSUER}/userinfo`, {
        headers: {
          authorization: `DPoP ${tokens.access_token}`,
          dpop: await proof('GET', `${ISSUER}/userinfo`, { accessToken: tokens.access_token, key: thief })
        }
      })
    )
    expect(response.status).toBe(400)
    expect((await response.json()).error).toBe('invalid_dpop_proof')
  })

  test('a proof without ath does not authorise the token', async () => {
    const tokens = await bound()
    const response = await provider.handle(
      new Request(`${ISSUER}/userinfo`, {
        headers: { authorization: `DPoP ${tokens.access_token}`, dpop: await proof('GET', `${ISSUER}/userinfo`) }
      })
    )
    expect((await response.json()).error_description).toContain('not bound to this access token')
  })

  test('a proof for another method or URI is refused', async () => {
    const tokens = await bound()
    const wrongUri = await provider.handle(
      new Request(`${ISSUER}/userinfo`, {
        headers: {
          authorization: `DPoP ${tokens.access_token}`,
          dpop: await proof('GET', `${ISSUER}/elsewhere`, { accessToken: tokens.access_token })
        }
      })
    )
    expect((await wrongUri.json()).error_description).toContain('bound to')
  })

  // NFR-S5: without this a captured proof is replayable for its whole window.
  test('a proof cannot be replayed', async () => {
    const tokens = await bound()
    const single = await proof('GET', `${ISSUER}/userinfo`, { accessToken: tokens.access_token })
    const headers = { authorization: `DPoP ${tokens.access_token}`, dpop: single }
    expect((await provider.handle(new Request(`${ISSUER}/userinfo`, { headers }))).status).toBe(200)
    const replayed = await provider.handle(new Request(`${ISSUER}/userinfo`, { headers }))
    expect((await replayed.json()).error_description).toContain('already been used')
  })

  test('a stale proof is refused', async () => {
    const tokens = await bound()
    const response = await provider.handle(
      new Request(`${ISSUER}/userinfo`, {
        headers: {
          authorization: `DPoP ${tokens.access_token}`,
          dpop: await proof('GET', `${ISSUER}/userinfo`, { accessToken: tokens.access_token, iat: Math.floor(Date.now() / 1000) - 600 })
        }
      })
    )
    expect((await response.json()).error_description).toContain('too old')
  })

  test('a proof with the wrong typ is refused', async () => {
    const tokens = await bound()
    const response = await provider.handle(
      new Request(`${ISSUER}/userinfo`, {
        headers: {
          authorization: `DPoP ${tokens.access_token}`,
          dpop: await proof('GET', `${ISSUER}/userinfo`, { accessToken: tokens.access_token, typ: 'JWT' })
        }
      })
    )
    expect((await response.json()).error_description).toContain('dpop+jwt')
  })
})

describe('DPoP through refresh', () => {
  test('the binding survives rotation', async () => {
    const first = await (await exchange(await codeFor(), { dpop: await proof('POST', `${ISSUER}/token`) })).json()
    const rotated = await provider.handle(
      new Request(`${ISSUER}/token`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', dpop: await proof('POST', `${ISSUER}/token`) },
        body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: first.refresh_token, client_id: 'rp' }).toString()
      })
    )
    expect((await rotated.json()).token_type).toBe('DPoP')
  })

  // Otherwise the constraint evaporates on the first refresh.
  test('a bound refresh token cannot be redeemed by a different key', async () => {
    const first = await (await exchange(await codeFor(), { dpop: await proof('POST', `${ISSUER}/token`) })).json()
    const thief = await generateKeyPair('ES256', { extractable: true })
    const response = await provider.handle(
      new Request(`${ISSUER}/token`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', dpop: await proof('POST', `${ISSUER}/token`, { key: thief }) },
        body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: first.refresh_token, client_id: 'rp' }).toString()
      })
    )
    expect((await response.json()).error_description).toContain('bound to a different key')
  })
})

describe('discovery', () => {
  test('advertises DPoP algorithms only when the feature is on', async () => {
    const on = await (await provider.handle(new Request(`${ISSUER}/.well-known/openid-configuration`))).json()
    expect(on.dpop_signing_alg_values_supported).toBeTruthy()

    const off = createProvider({ issuer: ISSUER, adapter })
    const body = await (await off.handle(new Request(`${ISSUER}/.well-known/openid-configuration`))).json()
    expect(body).not.toHaveProperty('dpop_signing_alg_values_supported')
  })
})
