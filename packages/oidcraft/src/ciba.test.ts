import { beforeEach, describe, expect, test } from 'bun:test'
import { decodeJwt } from 'jose'
import { memoryAdapter } from './adapters/memory'
import type { Adapter, Client } from './index'
import { createProvider, type Provider } from './provider'

const ISSUER = 'https://op.example.com'
const SECRET = 'shhh-a-long-enough-secret'

const client = (over: Partial<Client> = {}): Client => ({
  clientId: 'bank',
  clientSecret: SECRET,
  redirectUris: ['https://bank.example.com/cb'],
  grantTypes: ['urn:openid:params:grant-type:ciba'],
  responseTypes: ['code'],
  scopes: ['openid', 'profile', 'payments'],
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

const basic = (id = 'bank', secret = SECRET) => `Basic ${btoa(`${id}:${secret}`)}`

const post = (path: string, body: Record<string, string>, headers: Record<string, string> = {}, target = provider) =>
  target.handle(
    new Request(`${ISSUER}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers },
      body: new URLSearchParams(body).toString()
    })
  )

const build = (over: Record<string, unknown> = {}) =>
  createProvider({
    issuer: ISSUER,
    adapter,
    scopes: ['openid', 'profile', 'email', 'offline_access', 'payments'],
    features: { ciba: true },
    resolveCibaUser: ({ hint }) => (hint.value === 'ada@example.test' ? { accountId: 'ada' } : undefined),
    ...over
  } as Parameters<typeof createProvider>[0])

beforeEach(async () => {
  adapter = await memoryAdapter({ accounts })
  await adapter.clients.create?.(client())
  await adapter.clients.create?.(client({ clientId: 'pinger', backchannelTokenDeliveryMode: 'ping' }))
  provider = build()
})

const start = (over: Record<string, string> = {}, as = 'bank') =>
  post('/backchannel', { scope: 'openid profile payments', login_hint: 'ada@example.test', ...over }, { authorization: basic(as) })

const pollFor = (authReqId: string, as = 'bank') =>
  post('/token', { grant_type: 'urn:openid:params:grant-type:ciba', auth_req_id: authReqId }, { authorization: basic(as) })

const approve = async (authReqId: string, scopes = ['openid', 'profile', 'payments']) => {
  const session = { id: 's1', accountId: 'ada', authTime: new Date(), clients: ['bank'], expiresAt: new Date(Date.now() + 60_000) }
  await adapter.sessions.upsert(session)
  return provider.ciba.resolve(authReqId, { accountId: 'ada', sessionId: session.id, scopes })
}

describe('backchannel authentication', () => {
  test('issues an auth_req_id with an interval in poll mode', async () => {
    const body = await (await start()).json()
    expect(body.auth_req_id).toBeTruthy()
    expect(body.expires_in).toBeGreaterThan(0)
    expect(body.interval).toBeGreaterThan(0)
  })

  // The client never touches the user's browser, so identifying them is entirely ours.
  test('is refused outright without a resolveCibaUser', async () => {
    const bare = createProvider({ issuer: ISSUER, adapter, features: { ciba: true } })
    const response = await post('/backchannel', { scope: 'openid', login_hint: 'ada@example.test' }, { authorization: basic() }, bare)
    expect((await response.json()).error_description).toContain('resolveCibaUser')
  })

  test('a hint matching nobody is unknown_user_id', async () => {
    expect((await (await start({ login_hint: 'nobody@example.test' })).json()).error).toBe('unknown_user_id')
  })

  // OIDC CIBA 1.0 §7.1: resolving ambiguity by precedence lets a caller make us and an auditor
  // disagree about who was asked.
  test('exactly one hint is required', async () => {
    const none = await post('/backchannel', { scope: 'openid' }, { authorization: basic() })
    expect((await none.json()).error_description).toContain('is required')

    const both = await start({ id_token_hint: 'whatever' })
    expect((await both.json()).error_description).toContain('only one hint')
  })

  test('requires client authentication', async () => {
    expect((await post('/backchannel', { scope: 'openid', login_hint: 'ada@example.test' })).status).toBe(401)
  })

  test('refuses a scope the client may not have', async () => {
    expect((await (await start({ scope: 'openid admin' })).json()).error).toBe('invalid_scope')
  })

  test('ping mode requires a notification token, and then omits the interval', async () => {
    const missing = await start({}, 'pinger')
    expect((await missing.json()).error_description).toContain('client_notification_token')

    const body = await (await start({ client_notification_token: 'nt' }, 'pinger')).json()
    expect(body.auth_req_id).toBeTruthy()
    expect(body.interval).toBeUndefined()
  })

  test('the endpoint is absent unless the feature is on', async () => {
    const off = createProvider({ issuer: ISSUER, adapter })
    expect((await off.handle(new Request(`${ISSUER}/backchannel`, { method: 'POST' }))).status).toBe(404)
  })
})

describe('polling', () => {
  test('is authorization_pending until answered', async () => {
    const { auth_req_id } = await (await start()).json()
    expect((await (await pollFor(auth_req_id)).json()).error).toBe('authorization_pending')
  })

  test('polling too fast is slow_down', async () => {
    const { auth_req_id } = await (await start()).json()
    await pollFor(auth_req_id)
    expect((await (await pollFor(auth_req_id)).json()).error).toBe('slow_down')
  })

  test('a denial is access_denied', async () => {
    const { auth_req_id } = await (await start()).json()
    await provider.ciba.resolve(auth_req_id, { denied: true })
    expect((await (await pollFor(auth_req_id)).json()).error).toBe('access_denied')
  })

  test('approval yields real tokens', async () => {
    const { auth_req_id } = await (await start()).json()
    await approve(auth_req_id)
    const body = await (await pollFor(auth_req_id)).json()
    expect(body.access_token).toBeTruthy()
    expect(decodeJwt(body.id_token).sub).toBe('ada')
  })

  test('an auth_req_id is redeemed once', async () => {
    const { auth_req_id } = await (await start()).json()
    await approve(auth_req_id)
    expect((await pollFor(auth_req_id)).status).toBe(200)
    expect((await (await pollFor(auth_req_id)).json()).error).toBe('expired_token')
  })

  test('another client cannot poll it', async () => {
    const { auth_req_id } = await (await start()).json()
    expect((await (await pollFor(auth_req_id, 'pinger')).json()).error).toBe('invalid_grant')
  })

  test('an unknown auth_req_id is expired_token', async () => {
    expect((await (await pollFor('nope')).json()).error).toBe('expired_token')
  })

  // Ping mode delivers by notification; polling it would race the notification it replaces.
  test('a ping request cannot be polled', async () => {
    const { auth_req_id } = await (await start({ client_notification_token: 'nt' }, 'pinger')).json()
    expect((await (await pollFor(auth_req_id, 'pinger')).json()).error_description).toContain('delivered by ping')
  })
})

describe('resolution', () => {
  test('hands back the notification token so ping mode can be delivered', async () => {
    const { auth_req_id } = await (await start({ client_notification_token: 'nt' }, 'pinger')).json()
    const session = { id: 's2', accountId: 'ada', authTime: new Date(), clients: ['pinger'], expiresAt: new Date(Date.now() + 60_000) }
    await adapter.sessions.upsert(session)
    const result = await provider.ciba.resolve(auth_req_id, { accountId: 'ada', sessionId: session.id, scopes: ['openid'] })
    expect(result).toEqual({ approved: true, notify: 'nt' })
  })

  test('answering twice is refused', async () => {
    const { auth_req_id } = await (await start()).json()
    await provider.ciba.resolve(auth_req_id, { denied: true })
    expect(provider.ciba.resolve(auth_req_id, { denied: true })).rejects.toThrow(/already answered/)
  })

  test('an unknown request is refused', async () => {
    expect(provider.ciba.resolve('nope', { denied: true })).rejects.toThrow(/unknown or expired/)
  })
})

describe('discovery', () => {
  test('advertises CIBA only when the feature is on', async () => {
    const on = await (await provider.handle(new Request(`${ISSUER}/.well-known/openid-configuration`))).json()
    expect(on.backchannel_authentication_endpoint).toBe(`${ISSUER}/backchannel`)
    expect(on.grant_types_supported).toContain('urn:openid:params:grant-type:ciba')
    expect(on.backchannel_token_delivery_modes_supported).toEqual(['poll', 'ping'])

    const off = await (
      await createProvider({ issuer: ISSUER, adapter }).handle(new Request(`${ISSUER}/.well-known/openid-configuration`))
    ).json()
    expect(off).not.toHaveProperty('backchannel_authentication_endpoint')
  })
})
