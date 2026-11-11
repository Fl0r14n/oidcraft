import { describe, expect, test } from 'bun:test'
// #region imports
import { type Adapter, fromKv, generatedKeyStore, type KvEntry, type KvStore, type ReplayGuard } from '@oidcraft/adapter'
// #endregion imports
// #region conformance-import
import { adapterConformance } from '@oidcraft/adapter/conformance'
import { calculatePKCECodeChallenge, randomPKCECodeVerifier } from '@oidcraft/core'
import { createProvider, type Provider } from '@oidcraft/provider'

// #endregion conformance-import

// #region kv-store
const mapKv = (): KvStore => {
  const entries = new Map<string, { value: string; expiresAt: number }>()

  const live = (key: string) => {
    const entry = entries.get(key)
    if (entry && entry.expiresAt > Date.now()) return entry
    entries.delete(key)
    return undefined
  }

  const write = ({ key, value, ttl }: KvEntry) => {
    entries.set(key, { value, expiresAt: ttl === undefined ? Number.POSITIVE_INFINITY : Date.now() + ttl * 1000 })
  }

  return {
    async find(key) {
      const entry = live(key)
      return entry ? { key, value: entry.value } : undefined
    },
    async upsert(entry) {
      write(entry)
    },
    async destroy(key) {
      entries.delete(key)
    },
    async insert(entry) {
      if (live(entry.key)) return false
      write(entry)
      return true
    },
    async *scan(prefix) {
      for (const key of [...entries.keys()]) {
        const entry = key.startsWith(prefix) ? live(key) : undefined
        if (entry) yield { key, value: entry.value }
      }
    }
  }
}
// #endregion kv-store

// #region from-kv
const issuer = 'https://auth.example.com'

const adapter = fromKv(mapKv(), {
  keys: await generatedKeyStore(),
  accounts: {
    find: async accountId => ({ accountId, claims: {} }),
    claims: async accountId => ({ name: accountId })
  }
})

const provider = createProvider({ issuer, adapter, interactionUrl: `${issuer}/interaction` })
// #endregion from-kv

// #region racy-insert
const racy = (kv: KvStore): KvStore => ({
  ...kv,
  async insert(entry) {
    if (await kv.find(entry.key)) return false
    await kv.upsert(entry)
    return true
  }
})
// #endregion racy-insert

const REDIRECT = 'https://app.example.com/callback'

const register = (target: Adapter) =>
  target.clients.upsert?.({
    clientId: 'app',
    redirectUris: [REDIRECT],
    grantTypes: ['authorization_code', 'refresh_token'],
    responseTypes: ['code'],
    scopes: ['openid', 'profile', 'offline_access'],
    tokenEndpointAuthMethod: 'none',
    createdAt: new Date(),
    updatedAt: new Date()
  })

let people = 0

const signIn = async (op: Provider) => {
  const verifier = randomPKCECodeVerifier()
  const query = new URLSearchParams({
    client_id: 'app',
    redirect_uri: REDIRECT,
    response_type: 'code',
    scope: 'openid profile offline_access',
    code_challenge: await calculatePKCECodeChallenge(verifier),
    code_challenge_method: 'S256'
  })
  const idOf = (response: Response) => new URL(response.headers.get('location') as string).pathname.split('/').pop() as string
  const go = (url: string, cookie = '') => op.handle(new Request(url, { headers: { cookie } }))

  people += 1
  const login = await op.interactions.complete(idOf(await go(`${issuer}/authorize?${query}`)), { login: { accountId: `person-${people}` } })
  const cookie = (login.setCookie as string).split(';')[0] as string
  const consent = await op.interactions.complete(idOf(await go(login.redirectTo, cookie)), {
    consent: { scopes: ['openid', 'profile', 'offline_access'] }
  })
  const code = new URL((await go(consent.redirectTo, cookie)).headers.get('location') as string).searchParams.get('code') as string
  return { code, verifier }
}

const token = (op: Provider, body: Record<string, string>) =>
  op.handle(
    new Request(`${issuer}/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_id: 'app', ...body })
    })
  )

await register(adapter)

const redeem = (op: Provider, code: string, verifier: string) =>
  token(op, { grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: REDIRECT })

describe('a provider over a KvStore', () => {
  test('issues tokens, and a replayed code revokes everything the grant produced', async () => {
    const { code, verifier } = await signIn(provider)

    const first = await redeem(provider, code, verifier)
    expect(first.status).toBe(200)
    const tokens = await first.json()
    expect(tokens.refresh_token).toBeString()

    const replay = await redeem(provider, code, verifier)
    expect(replay.status).toBe(400)
    expect((await replay.json()).error).toBe('invalid_grant')

    const refresh = await token(provider, { grant_type: 'refresh_token', refresh_token: tokens.refresh_token })
    expect((await refresh.json()).error).toBe('invalid_grant')
  })

  test('insert writes once, and again only after the entry lapses', async () => {
    const kv = mapKv()
    const results = await Promise.all(Array.from({ length: 8 }, () => kv.insert({ key: 'once', value: '1' })))
    expect(results.filter(Boolean)).toHaveLength(1)

    expect(await kv.insert({ key: 'short', value: '1', ttl: 0.05 })).toBe(true)
    expect(await kv.insert({ key: 'short', value: '1', ttl: 0.05 })).toBe(false)
    await Bun.sleep(60)
    expect(await kv.find('short')).toBeUndefined()
    expect(await kv.insert({ key: 'short', value: '1', ttl: 0.05 })).toBe(true)
  })

  test('scan yields only its prefix and tolerates deletes while it runs', async () => {
    const kv = mapKv()
    for (const key of ['grant/a/1', 'grant/a/2', 'grant/b/1']) await kv.upsert({ key, value: '' })
    const seen: string[] = []
    for await (const { key } of kv.scan('grant/a/')) {
      seen.push(key)
      await kv.destroy(key)
    }
    expect(seen).toEqual(['grant/a/1', 'grant/a/2'])
    expect(await kv.find('grant/b/1')).toEqual({ key: 'grant/b/1', value: '' })
  })
})

describe('an insert that reads and then writes', () => {
  test('lets every parallel caller win', async () => {
    const kv = racy(mapKv())
    const results = await Promise.all(Array.from({ length: 8 }, () => kv.insert({ key: 'once', value: '1' })))
    expect(results.filter(Boolean)).toHaveLength(8)
  })

  test('where the atomic one lets exactly one redemption of a code win', async () => {
    const { code, verifier } = await signIn(provider)
    const statuses = (await Promise.all([redeem(provider, code, verifier), redeem(provider, code, verifier)])).map(r => r.status)
    expect(statuses.sort()).toEqual([200, 400])
  })
})

describe('replacing one store', () => {
  // #region replace-store
  const claimed = new Map<string, number>()

  const replay: ReplayGuard = {
    async claim(namespace, value, ttl) {
      const key = `${namespace}/${value}`
      if ((claimed.get(key) ?? 0) > Date.now()) return false
      claimed.set(key, Date.now() + ttl * 1000)
      return true
    }
  }

  const custom: Adapter = { ...adapter, replay }
  // #endregion replace-store

  test('the provider accepts it and the guard admits a value once', async () => {
    const op = createProvider({ issuer, adapter: custom, interactionUrl: `${issuer}/interaction` })
    expect((await op.handle(new Request(`${issuer}/.well-known/openid-configuration`))).status).toBe(200)
    expect(await custom.replay.claim('jti', 'abc', 60)).toBe(true)
    expect(await custom.replay.claim('jti', 'abc', 60)).toBe(false)
    expect(await custom.replay.claim('dpop', 'abc', 60)).toBe(true)
  })
})

// #region conformance
describe('a Map behind a KvStore', () => {
  const accounts = { find: async (accountId: string) => ({ accountId, claims: {} }), claims: async () => ({}) }
  const create = async () => fromKv(mapKv(), { keys: await generatedKeyStore(), accounts })

  for (const check of adapterConformance(create, { implements: ['identities', 'credentials', 'realms'] })) {
    test(check.name, check.run)
  }
})
// #endregion conformance
