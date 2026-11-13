import { expect, test } from 'bun:test'
import { fromKv, generatedKeyStore, hashClientSecret, type KvStore } from '@oidcraft/adapter'
import { memoryKv } from '@oidcraft/adapter/memory'
import { randomString, sha256 } from '@oidcraft/core'
import { base64url } from 'jose'
import type { Client } from './index'
import { createProvider } from './provider'

/** The browser-binding cookie the redirect to an interaction set, as the browser would send it back (FR-I2). */
const browserOf = (response: Response) => response.headers.get('set-cookie')?.split(';')[0] ?? null

const ISSUER = 'https://op.example.com'
const REDIRECT = 'https://rp.example.com/cb'
const SECRET = 'a-long-enough-client-secret'
const SECRET_HASH = await hashClientSecret(SECRET)

/** Records every prefix scanned, so a request path reading a whole family of records shows up by name. */
const recording = (kv: KvStore) => {
  const scanned: string[] = []
  const store: KvStore = {
    ...kv,
    scan(prefix) {
      scanned.push(prefix)
      return kv.scan(prefix)
    }
  }
  return { store, scanned }
}

// One record's own keys, e.g. `session-client/<id>/`: something after the family, and a closing slash.
const NARROW = /^[a-z-]+\/.+\/$/

// NFR-P1: no request path scans a family of records, whatever the store holds.
test('a sign-in, a refresh, UserInfo, a revocation and a logout scan no whole family of records', async () => {
  const { store, scanned } = recording(memoryKv())
  const accounts = {
    async find(accountId: string) {
      return { accountId, claims: {} }
    },
    async claims() {
      return { name: 'Ada' }
    }
  }
  const adapter = fromKv(store, { keys: await generatedKeyStore(), accounts })
  const client: Client = {
    clientId: 'rp',
    clientSecretHash: SECRET_HASH,
    redirectUris: [REDIRECT],
    grantTypes: ['authorization_code', 'refresh_token'],
    responseTypes: ['code'],
    scopes: ['openid', 'profile', 'offline_access'],
    tokenEndpointAuthMethod: 'client_secret_basic',
    createdAt: new Date(),
    updatedAt: new Date()
  }
  await adapter.clients.upsert?.(client)
  const provider = createProvider({ issuer: ISSUER, adapter, interactionUrl: `${ISSUER}/interaction` })

  const verifier = randomString() + randomString()
  const params = new URLSearchParams({
    client_id: 'rp',
    redirect_uri: REDIRECT,
    response_type: 'code',
    scope: 'openid profile offline_access',
    code_challenge: base64url.encode(await sha256(verifier)),
    code_challenge_method: 'S256'
  })
  const authorize = (cookie = '') => provider.handle(new Request(`${ISSUER}/authorize?${params}`, { headers: cookie ? { cookie } : {} }))
  const idOf = (response: Response) => (response.headers.get('location') as string).split('/').pop() as string
  const post = (path: string, body: Record<string, string>) =>
    provider.handle(
      new Request(`${ISSUER}${path}`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: `Basic ${btoa(`rp:${SECRET}`)}` },
        body: new URLSearchParams(body).toString()
      })
    )

  const started = await authorize()
  const login = await provider.interactions.complete(idOf(started), { login: { accountId: 'ada' } }, browserOf(started))
  const cookie = (login.setCookie as string).split(';')[0] as string
  const asked = await provider.handle(new Request(login.redirectTo, { headers: { cookie } }))
  const consent = await provider.interactions.complete(
    idOf(asked),
    { consent: { scopes: ['openid', 'profile', 'offline_access'] } },
    browserOf(asked)
  )
  const granted = await provider.handle(new Request(consent.redirectTo, { headers: { cookie } }))
  const code = new URL(granted.headers.get('location') as string).searchParams.get('code') as string
  const issued = await (
    await post('/token', { grant_type: 'authorization_code', code, redirect_uri: REDIRECT, code_verifier: verifier })
  ).json()
  expect(issued.access_token).toBeTruthy()

  // A second authorization, now with a session and a grant to find.
  expect(new URL((await authorize(cookie)).headers.get('location') as string).searchParams.get('code')).toBeTruthy()
  const refreshed = await (await post('/token', { grant_type: 'refresh_token', refresh_token: issued.refresh_token })).json()
  expect(refreshed.access_token).toBeTruthy()
  const userinfo = await provider.handle(
    new Request(`${ISSUER}/userinfo`, { headers: { authorization: `Bearer ${refreshed.access_token}` } })
  )
  expect(userinfo.status).toBe(200)
  expect((await post('/revoke', { token: refreshed.refresh_token })).status).toBe(200)
  const out = await provider.handle(new Request(`${ISSUER}/session/end?id_token_hint=${issued.id_token}`, { headers: { cookie } }))
  expect(out.status).toBe(200)

  expect(scanned.filter(prefix => !NARROW.test(prefix))).toEqual([])
})
