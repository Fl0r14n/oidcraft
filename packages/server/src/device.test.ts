import { beforeEach, describe, expect, test } from 'bun:test'
import { decodeJwt } from 'jose'
import { memoryAdapter } from './adapters/memory'
import { normalizeUserCode, userCode } from './endpoints/device'
import type { Adapter, Client } from './index'
import { createProvider, type Provider } from './provider'
import { sectorOf } from './subjects'

const ISSUER = 'https://op.example.com'
const SECRET = 'shhh-a-long-enough-secret'

const client = (over: Partial<Client> = {}): Client => ({
  clientId: 'tv',
  clientSecret: SECRET,
  redirectUris: ['https://tv.example.com/cb'],
  grantTypes: ['urn:ietf:params:oauth:grant-type:device_code', 'refresh_token'],
  responseTypes: ['code'],
  scopes: ['openid', 'profile', 'offline_access'],
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
    return { name: 'Ada' }
  }
}

let adapter: Adapter
let provider: Provider

const basic = (id = 'tv', secret = SECRET) => `Basic ${btoa(`${id}:${secret}`)}`

const post = (path: string, body: Record<string, string>, headers: Record<string, string> = {}) =>
  provider.handle(
    new Request(`${ISSUER}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers },
      body: new URLSearchParams(body).toString()
    })
  )

beforeEach(async () => {
  adapter = await memoryAdapter({ accounts })
  await adapter.clients.create?.(client())
  provider = createProvider({ issuer: ISSUER, adapter, features: { deviceFlow: true } })
})

const start = async (scope = 'openid profile offline_access') =>
  (await post('/device/authorize', { scope }, { authorization: basic() })).json()

const poll = (deviceCode: string) =>
  post('/token', { grant_type: 'urn:ietf:params:oauth:grant-type:device_code', device_code: deviceCode }, { authorization: basic() })

describe('user codes', () => {
  // RFC 8628 §6.1: this decides whether the flow works when read off a television.
  test('avoid the characters a person misreads', () => {
    for (let i = 0; i < 200; i++) expect(userCode()).toMatch(/^[BCDFGHJKMNPQRSTVWXYZ2-9]{4}-[BCDFGHJKMNPQRSTVWXYZ2-9]{4}$/)
  })

  test('are normalised the way a person types them', () => {
    expect(normalizeUserCode('wdjb-mjht')).toBe('WDJBMJHT')
    expect(normalizeUserCode(' WDJB MJHT ')).toBe('WDJBMJHT')
  })
})

describe('device authorization', () => {
  test('issues a device code, a user code and both verification URIs', async () => {
    const body = await start()
    expect(body.device_code).toBeTruthy()
    expect(body.user_code).toMatch(/-/)
    expect(body.verification_uri).toBe(`${ISSUER}/device`)
    expect(body.verification_uri_complete).toContain(encodeURIComponent(body.user_code))
    expect(body.interval).toBeGreaterThan(0)
  })

  test('requires client authentication', async () => {
    expect((await post('/device/authorize', { scope: 'openid' })).status).toBe(401)
  })

  test('refuses a scope the client may not have', async () => {
    const response = await post('/device/authorize', { scope: 'openid admin' }, { authorization: basic() })
    expect((await response.json()).error).toBe('invalid_scope')
  })
})

describe('polling', () => {
  test('is authorization_pending until someone approves', async () => {
    const { device_code } = await start()
    const response = await poll(device_code)
    expect(response.status).toBe(400)
    expect((await response.json()).error).toBe('authorization_pending')
  })

  // RFC 8628 §3.5: a device that ignores `interval` is exactly the one to rate-limit.
  test('polling too fast is slow_down, and the interval grows', async () => {
    const { device_code } = await start()
    await poll(device_code)
    const response = await poll(device_code)
    expect((await response.json()).error).toBe('slow_down')
  })

  test('an unknown device code is expired_token', async () => {
    expect((await (await poll('never-existed')).json()).error).toBe('expired_token')
  })

  test('another client cannot poll it', async () => {
    await adapter.clients.create?.(client({ clientId: 'other' }))
    const { device_code } = await start()
    const response = await post(
      '/token',
      { grant_type: 'urn:ietf:params:oauth:grant-type:device_code', device_code },
      { authorization: basic('other') }
    )
    expect((await response.json()).error).toBe('invalid_grant')
  })

  test('a denied request is access_denied', async () => {
    const { device_code, user_code } = await start()
    await provider.device.resolve(user_code, { denied: true })
    expect((await (await poll(device_code)).json()).error).toBe('access_denied')
  })
})

describe('approval', () => {
  const approve = async (userCodeTyped: string) => {
    const session = { id: 's1', accountId: 'ada', authTime: new Date(), clients: ['tv'], expiresAt: new Date(Date.now() + 60_000) }
    await adapter.sessions.upsert(session)
    return provider.device.resolve(userCodeTyped, {
      accountId: 'ada',
      sessionId: session.id,
      scopes: ['openid', 'profile', 'offline_access']
    })
  }

  test('a screen can look up what was typed before approving it', async () => {
    const { user_code } = await start()
    const found = await provider.device.find(user_code.toLowerCase())
    expect(found?.client.clientId).toBe('tv')
    expect(found?.payload.scopes).toContain('profile')
  })

  test('approval lets the next poll succeed with real tokens', async () => {
    const { device_code, user_code } = await start()
    await approve(user_code)

    const response = await poll(device_code)
    expect(response.status).toBe(200)
    const body = await response.json()
    expect(body.access_token).toBeTruthy()
    expect(body.refresh_token).toBeTruthy()
    expect(decodeJwt(body.id_token).sub).toBe('ada')
  })

  // Approval redeems once, however many times the device polls.
  test('a device code cannot be redeemed twice', async () => {
    const { device_code, user_code } = await start()
    await approve(user_code)
    expect((await poll(device_code)).status).toBe(200)
    expect((await (await poll(device_code)).json()).error).toBe('expired_token')
  })

  test('answering the same code twice is refused', async () => {
    const { user_code } = await start()
    await approve(user_code)
    expect(provider.device.resolve(user_code, { denied: true })).rejects.toThrow(/already been answered/)
  })

  test('an unknown code is refused', async () => {
    expect(provider.device.find('ZZZZ-ZZZZ')).resolves.toBeUndefined()
    expect(provider.device.resolve('ZZZZ-ZZZZ', { denied: true })).rejects.toThrow(/not one we are waiting for/)
  })

  test('the endpoint is absent unless the feature is on', async () => {
    const off = createProvider({ issuer: ISSUER, adapter })
    expect((await off.handle(new Request(`${ISSUER}/device/authorize`, { method: 'POST' }))).status).toBe(404)
  })
})

describe('pairwise subjects', () => {
  const pairwise = async () => {
    const paired = await memoryAdapter({ accounts })
    await paired.clients.create?.(client({ subjectType: 'pairwise' }))
    await paired.clients.create?.(client({ clientId: 'other', subjectType: 'pairwise', redirectUris: ['https://other.example.com/cb'] }))
    return createProvider({ issuer: ISSUER, adapter: paired, features: { deviceFlow: true }, pairwiseSalt: 'a-salt' })
  }

  test('a pairwise sub is not the account id', async () => {
    provider = await pairwise()
    const { device_code, user_code } = await start()
    await adapter.sessions.upsert({
      id: 's1',
      accountId: 'ada',
      authTime: new Date(),
      clients: ['tv'],
      expiresAt: new Date(Date.now() + 60_000)
    })
    const paired = provider.config.adapter
    await paired.sessions.upsert({
      id: 's1',
      accountId: 'ada',
      authTime: new Date(),
      clients: ['tv'],
      expiresAt: new Date(Date.now() + 60_000)
    })
    await provider.device.resolve(user_code, { accountId: 'ada', sessionId: 's1', scopes: ['openid'] })

    const body = await (await poll(device_code)).json()
    const sub = decodeJwt(body.id_token).sub as string
    expect(sub).not.toBe('ada')
    expect(sub.length).toBeGreaterThan(20)
  })

  // FR-C18: two relying parties must not be able to recognise the same person.
  test('two clients see different subjects for one account', async () => {
    const salted = await pairwise()
    const a = await salted.config.adapter.clients.find('tv')
    const b = await salted.config.adapter.clients.find('other')
    const { subjectFor } = await import('./subjects')
    expect(await subjectFor(salted.config, a as Client, 'ada')).not.toBe(await subjectFor(salted.config, b as Client, 'ada'))
  })

  test('the sector is the redirect host unless one is declared', () => {
    expect(sectorOf(client())).toBe('tv.example.com')
    expect(sectorOf(client({ sectorIdentifierUri: 'https://shared.example.com/uris.json' }))).toBe('shared.example.com')
  })

  // Otherwise the subject would depend on which redirect URI happened to be used.
  test('redirect URIs across hosts need a declared sector', () => {
    expect(() => sectorOf(client({ redirectUris: ['https://a.example.com/cb', 'https://b.example.com/cb'] }))).toThrow(
      /sector_identifier_uri/
    )
  })

  test('pairwise without a salt is refused at construction', async () => {
    const plain = await memoryAdapter()
    expect(() => createProvider({ issuer: ISSUER, adapter: plain, subjectType: 'pairwise' })).toThrow(/pairwiseSalt/)
  })

  test('discovery advertises pairwise only when it can actually issue them', async () => {
    const off = await (
      await createProvider({ issuer: ISSUER, adapter }).handle(new Request(`${ISSUER}/.well-known/openid-configuration`))
    ).json()
    expect(off.subject_types_supported).toEqual(['public'])
    const on = await (await (await pairwise()).handle(new Request(`${ISSUER}/.well-known/openid-configuration`))).json()
    expect(on.subject_types_supported).toContain('pairwise')
  })
})
