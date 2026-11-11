import type { Adapter, Artifact, Client, FullAdapter, Grant, Realm, Session } from '@oidcraft/provider'

/** The stores beyond the core seven. A check that needs one runs only when the adapter claims it. */
export type OptionalStore = 'identities' | 'credentials' | 'realms'

export type ConformanceOptions = {
  /** The optional stores this adapter implements; each is then held to the same checks as the core. */
  implements?: OptionalStore[]
}

/** One guarantee. `run` resolves when the adapter keeps it and throws a `ConformanceError` when it does not. */
export type ConformanceCheck = {
  name: string
  run: () => Promise<void>
}

export class ConformanceError extends Error {
  override name = 'ConformanceError'
}

const comparable = (value: unknown): unknown => {
  if (value instanceof Date) return { date: value.toISOString() }
  if (Array.isArray(value)) return value.map(comparable)
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value)
        .filter(([, field]) => field !== undefined)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([key, field]) => [key, comparable(field)])
    )
  }
  return value
}

const show = (value: unknown) => (value === undefined ? 'undefined' : JSON.stringify(comparable(value)))

const same = (actual: unknown, expected: unknown, what: string) => {
  if (show(actual) !== show(expected)) throw new ConformanceError(`${what}: expected ${show(expected)}, got ${show(actual)}`)
}

const holds = (condition: boolean, what: string) => {
  if (!condition) throw new ConformanceError(what)
}

const isDate = (value: unknown, what: string) => holds(value instanceof Date && !Number.isNaN(value.getTime()), `${what} is not a Date`)

const soon = (seconds = 60) => new Date(Date.now() + seconds * 1000)
const past = () => new Date(Date.now() - 1000)

const client = (clientId: string): Client => ({
  clientId,
  redirectUris: [`https://rp.example.com/${clientId}`],
  grantTypes: ['authorization_code'],
  responseTypes: ['code'],
  scopes: ['openid'],
  tokenEndpointAuthMethod: 'none',
  createdAt: new Date(),
  updatedAt: new Date()
})

const artifact = (over: Partial<Artifact> = {}): Artifact => ({
  id: 'a1',
  kind: 'authorization_code',
  clientId: 'c1',
  payload: {},
  expiresAt: soon(),
  ...over
})

const session = (over: Partial<Session> = {}): Session => ({
  id: 's1',
  accountId: 'u1',
  authTime: new Date(),
  clients: ['c1'],
  expiresAt: soon(),
  ...over
})

const grant = (over: Partial<Grant> = {}): Grant => ({
  id: 'g1',
  accountId: 'u1',
  clientId: 'c1',
  scopes: ['openid'],
  claims: [],
  resources: {},
  createdAt: new Date(),
  ...over
})

const credential = (accountId: string, username: string) => ({
  accountId,
  username,
  passwordHash: '$argon2id$stub',
  claims: { name: 'Ada' },
  failedAttempts: 0,
  createdAt: new Date(1_000),
  updatedAt: new Date(2_000)
})

const realm = (id: string): Realm => ({
  id,
  displayName: 'Acme',
  enabled: true,
  settings: { brand: { accent: '#123456' }, upstreams: ['google'] },
  createdAt: new Date(1_000),
  updatedAt: new Date(2_000)
})

const parallel = <T>(count: number, task: (index: number) => Promise<T>) =>
  Promise.all(Array.from({ length: count }, (_, index) => task(index)))

const winners = (results: unknown[]) => results.filter(Boolean).length

/**
 * The storage guarantees the protocol relies on, as checks any test runner can run: memory, Drizzle,
 * Kysely, TypeORM and Redis all pass them, which is what makes them interchangeable (FR-A4, FR-A6).
 * Each check builds a fresh adapter with `create`, so they are independent and may run in any order.
 *
 * ```ts
 * for (const check of adapterConformance(() => myAdapter(), { implements: ['identities'] })) test(check.name, check.run)
 * ```
 */
export const adapterConformance = (create: () => Adapter | Promise<Adapter>, options: ConformanceOptions = {}) => {
  const claimed = new Set(options.implements ?? [])
  const full = async () => (await create()) as FullAdapter
  const checks: (ConformanceCheck & { needs?: OptionalStore })[] = [
    {
      name: 'a missing record is undefined, never a throw',
      run: async () => {
        const adapter = await full()
        same(await adapter.clients.find('nope'), undefined, 'clients.find of an unknown id')
        same(await adapter.artifacts.find('authorization_code', 'nope'), undefined, 'artifacts.find of an unknown id')
        same(await adapter.sessions.find('nope'), undefined, 'sessions.find of an unknown id')
        same(await adapter.grants.find('nope'), undefined, 'grants.find of an unknown id')
      }
    },
    {
      name: 'a client round-trips',
      run: async () => {
        const adapter = await full()
        await adapter.clients.upsert?.(client('c1'))
        const found = await adapter.clients.find('c1')
        same(found?.clientId, 'c1', 'clientId')
        same(found?.redirectUris, ['https://rp.example.com/c1'], 'redirectUris')
        isDate(found?.createdAt, 'createdAt')
      }
    },
    {
      name: 'destroying a client removes it',
      run: async () => {
        const adapter = await full()
        await adapter.clients.upsert?.(client('c1'))
        await adapter.clients.destroy?.('c1')
        same(await adapter.clients.find('c1'), undefined, 'a destroyed client')
      }
    },
    {
      name: 'an artifact round-trips with its dates intact',
      run: async () => {
        const adapter = await full()
        await adapter.artifacts.upsert(artifact())
        const found = await adapter.artifacts.find('authorization_code', 'a1')
        same(found?.id, 'a1', 'id')
        isDate(found?.expiresAt, 'expiresAt')
      }
    },
    {
      name: 'kind is part of the identity, so two kinds may share an id',
      run: async () => {
        const adapter = await full()
        await adapter.artifacts.upsert(artifact({ id: 'same', kind: 'authorization_code' }))
        await adapter.artifacts.upsert(artifact({ id: 'same', kind: 'refresh_token' }))
        same((await adapter.artifacts.find('authorization_code', 'same'))?.kind, 'authorization_code', 'the code')
        same((await adapter.artifacts.find('refresh_token', 'same'))?.kind, 'refresh_token', 'the refresh token')
      }
    },
    {
      // FR-T5: storage enforces expiry, so a missed prune cycle still cannot serve a dead token.
      name: 'an expired artifact is never served',
      run: async () => {
        const adapter = await full()
        await adapter.artifacts.upsert(artifact({ expiresAt: past() }))
        same(await adapter.artifacts.find('authorization_code', 'a1'), undefined, 'an expired artifact')
      }
    },
    {
      // FR-T4: consuming marks it; replaying a consumed code is what revokes the grant.
      name: 'consume marks the artifact without destroying it',
      run: async () => {
        const adapter = await full()
        await adapter.artifacts.upsert(artifact())
        await adapter.artifacts.consume('authorization_code', 'a1')
        isDate((await adapter.artifacts.find('authorization_code', 'a1'))?.consumedAt, 'consumedAt')
      }
    },
    {
      // NFR-S4: the race a check-then-write loses — two redemptions in flight at once.
      name: 'of parallel consumes, exactly one wins',
      run: async () => {
        const adapter = await full()
        await adapter.artifacts.upsert(artifact())
        same(winners(await parallel(8, () => adapter.artifacts.consume('authorization_code', 'a1'))), 1, 'consumes that won')
      }
    },
    {
      name: 'consume refuses what is unknown or expired',
      run: async () => {
        const adapter = await full()
        same(await adapter.artifacts.consume('authorization_code', 'missing'), false, 'consume of an unknown artifact')
        await adapter.artifacts.upsert(artifact({ expiresAt: past() }))
        same(await adapter.artifacts.consume('authorization_code', 'a1'), false, 'consume of an expired artifact')
      }
    },
    {
      // A device poll reads, a redemption consumes, the poll writes back what it read.
      name: 'an upsert never revives a consumed artifact',
      run: async () => {
        const adapter = await full()
        await adapter.artifacts.upsert(artifact())
        const stale = await adapter.artifacts.find('authorization_code', 'a1')
        same(await adapter.artifacts.consume('authorization_code', 'a1'), true, 'the first consume')
        await adapter.artifacts.upsert({ ...(stale as Artifact), payload: { polled: true } })
        isDate((await adapter.artifacts.find('authorization_code', 'a1'))?.consumedAt, 'consumedAt after a stale upsert')
        same(await adapter.artifacts.consume('authorization_code', 'a1'), false, 'a second consume after a stale upsert')
      }
    },
    {
      name: 'destroy removes the artifact',
      run: async () => {
        const adapter = await full()
        await adapter.artifacts.upsert(artifact())
        await adapter.artifacts.destroy('authorization_code', 'a1')
        same(await adapter.artifacts.find('authorization_code', 'a1'), undefined, 'a destroyed artifact')
      }
    },
    {
      // The query the protocol needs most and a blob store handles worst (FR-A5).
      name: 'revokeByGrantId removes every artifact of that grant and nothing else',
      run: async () => {
        const adapter = await full()
        await adapter.artifacts.upsert(artifact({ id: 'a1', kind: 'authorization_code', grantId: 'g1' }))
        await adapter.artifacts.upsert(artifact({ id: 'a2', kind: 'refresh_token', grantId: 'g1' }))
        await adapter.artifacts.upsert(artifact({ id: 'a3', kind: 'refresh_token', grantId: 'g2' }))
        await adapter.artifacts.revokeByGrantId('g1')
        same(await adapter.artifacts.find('authorization_code', 'a1'), undefined, "the revoked grant's code")
        same(await adapter.artifacts.find('refresh_token', 'a2'), undefined, "the revoked grant's refresh token")
        same((await adapter.artifacts.find('refresh_token', 'a3'))?.id, 'a3', "another grant's refresh token")
      }
    },
    {
      name: 'a device code is reachable by its user code',
      run: async () => {
        const adapter = await full()
        holds(typeof adapter.artifacts.findByUserCode === 'function', 'artifacts.findByUserCode is missing, so the device grant cannot run')
        await adapter.artifacts.upsert(artifact({ id: 'd1', kind: 'device_code', payload: { userCode: 'WDJB-MJHT' } }))
        same((await adapter.artifacts.findByUserCode?.('WDJB-MJHT'))?.id, 'd1', 'the device code found by its user code')
      }
    },
    {
      name: 'sessions round-trip and list by account',
      run: async () => {
        const adapter = await full()
        await adapter.sessions.upsert(session())
        await adapter.sessions.upsert(session({ id: 's2' }))
        await adapter.sessions.upsert(session({ id: 's3', accountId: 'u2' }))
        same((await adapter.sessions.listForAccount('u1')).map(found => found.id).sort(), ['s1', 's2'], "u1's sessions")
      }
    },
    {
      // FR-C11: logout notifies every client on this list, so a sign-in racing another must not drop one.
      name: 'of parallel addClient calls, every client is recorded',
      run: async () => {
        const adapter = await full()
        await adapter.sessions.upsert(session())
        const added = Array.from({ length: 12 }, (_, index) => `rp-${index}`)
        await Promise.all(added.map(clientId => adapter.sessions.addClient('s1', clientId)))
        same((await adapter.sessions.find('s1'))?.clients.sort(), ['c1', ...added].sort(), "the session's clients")
        same((await adapter.sessions.listForAccount('u1'))[0]?.clients.length, 13, "the listed session's clients")
      }
    },
    {
      name: 'addClient leaves a missing session missing',
      run: async () => {
        const adapter = await full()
        await adapter.sessions.addClient('nope', 'rp')
        same(await adapter.sessions.find('nope'), undefined, 'a session addClient was called on')
        await adapter.sessions.upsert(session())
        await adapter.sessions.destroy('s1')
        await adapter.sessions.addClient('s1', 'rp-2')
        same(await adapter.sessions.find('s1'), undefined, 'a destroyed session addClient was called on')
      }
    },
    {
      name: 'an expired session is never served',
      run: async () => {
        const adapter = await full()
        await adapter.sessions.upsert(session({ expiresAt: past() }))
        same(await adapter.sessions.find('s1'), undefined, 'an expired session')
      }
    },
    {
      name: 'a grant is reachable by account and client',
      run: async () => {
        const adapter = await full()
        await adapter.grants.upsert(grant())
        same((await adapter.grants.findByAccountAndClient('u1', 'c1'))?.id, 'g1', 'the grant by account and client')
        same(await adapter.grants.findByAccountAndClient('u1', 'other'), undefined, 'a grant for another client')
        same(
          (await adapter.grants.listForAccount('u1')).map(found => found.id),
          ['g1'],
          "u1's grants"
        )
      }
    },
    {
      // NFR-S5: the guard is what makes a jti or a DPoP proof one-shot.
      name: 'the replay guard admits a value once',
      run: async () => {
        const adapter = await full()
        same(await adapter.replay.claim('jti', 'abc', 60), true, 'the first claim')
        same(await adapter.replay.claim('jti', 'abc', 60), false, 'a second claim of the same value')
        same(await adapter.replay.claim('dpop', 'abc', 60), true, 'the same value in another namespace')
      }
    },
    {
      name: 'of parallel claims, exactly one wins',
      run: async () => {
        const adapter = await full()
        same(winners(await parallel(8, () => adapter.replay.claim('jti', 'race', 60))), 1, 'claims that won')
      }
    },
    {
      name: 'a lapsed claim can be made again',
      run: async () => {
        const adapter = await full()
        same(await adapter.replay.claim('jti', 'short', 0), true, 'a claim that lapses at once')
        same(await adapter.replay.claim('jti', 'short', 60), true, 'the same claim after it lapsed')
      }
    },
    {
      name: 'keys are available and carry an algorithm',
      run: async () => {
        const adapter = await full()
        const keys = await adapter.keys.active()
        holds(keys.length > 0, 'keys.active() returned no keys')
        holds(Boolean(keys[0]?.alg), 'the active key has no alg')
        holds(Boolean(keys[0]?.kid), 'the active key has no kid')
      }
    },
    {
      // FR-F8: upstream back-channel logout arrives keyed by the upstream session, not ours.
      name: 'sessions are reachable by their upstream session',
      needs: 'identities',
      run: async () => {
        const adapter = await full()
        holds(
          typeof adapter.sessions.findByUpstreamSession === 'function',
          'sessions.findByUpstreamSession is missing, which brokering needs'
        )
        await adapter.sessions.upsert(session({ idp: 'entra', upstreamSessionId: 'up-1' }))
        await adapter.sessions.upsert(session({ id: 's2', idp: 'entra', upstreamSessionId: 'up-2' }))
        same(
          (await adapter.sessions.findByUpstreamSession('entra', 'up-1'))?.map(found => found.id),
          ['s1'],
          'sessions of upstream session up-1'
        )
      }
    },
    {
      // FR-F5: linking is by (provider, subject) and nothing else.
      name: 'a linked identity is kept and removed by provider and subject',
      needs: 'identities',
      run: async () => {
        const adapter = await full()
        await adapter.identities.upsert({ accountId: 'u1', provider: 'google', subject: 'g-1', claims: {}, linkedAt: new Date() })
        same((await adapter.identities.find('google', 'g-1'))?.accountId, 'u1', 'the identity by provider and subject')
        same(await adapter.identities.find('entra', 'g-1'), undefined, 'the same subject at another provider')
        await adapter.identities.destroy('google', 'g-1')
        same(await adapter.identities.find('google', 'g-1'), undefined, 'a destroyed identity')
      }
    },
    {
      // FR-I7: a username belongs to one account, even when two sign-ups race for it.
      name: 'a credential is created once per account and per username, atomically',
      needs: 'credentials',
      run: async () => {
        const adapter = await full()
        same(winners(await parallel(8, index => adapter.credentials.create(credential(`a${index}`, 'ada')))), 1, 'creates that won')
        const winner = (await adapter.credentials.findByUsername('ada'))?.accountId as string
        same(await adapter.credentials.create(credential(winner, 'grace')), false, 'a second credential for the same account')
        same(await adapter.credentials.findByUsername('grace'), undefined, 'the refused username')
      }
    },
    {
      name: 'a credential round-trips, by account and by username',
      needs: 'credentials',
      run: async () => {
        const adapter = await full()
        same(await adapter.credentials.create(credential('a1', 'ada')), true, 'the first create')
        const totp = { secret: 'v1.iv.ct', confirmedAt: new Date(3_000) }
        const stored = { ...credential('a1', 'ada'), totp, recoveryCodes: ['h1', 'h2'], failedAttempts: 2, lockedUntil: new Date(4_000) }
        await adapter.credentials.upsert(stored)
        same(await adapter.credentials.findByUsername('ada'), stored, 'the credential by username')
        same((await adapter.credentials.find('a1'))?.username, 'ada', 'the credential by account')
        await adapter.credentials.destroy('a1')
        same(await adapter.credentials.find('a1'), undefined, 'a destroyed credential by account')
        same(await adapter.credentials.findByUsername('ada'), undefined, 'a destroyed credential by username')
        same(await adapter.credentials.create(credential('a2', 'ada')), true, 'reusing a freed username')
      }
    },
    {
      // FR-M4: two operators creating one realm must not both provision it.
      name: 'a realm is created once, atomically',
      needs: 'realms',
      run: async () => {
        const adapter = await full()
        same(winners(await parallel(8, () => adapter.realms.create(realm('acme')))), 1, 'creates that won')
        same(await adapter.realms.create(realm('acme')), false, 'a second create')
      }
    },
    {
      name: 'a realm round-trips, lists and is removed',
      needs: 'realms',
      run: async () => {
        const adapter = await full()
        await adapter.realms.create(realm('acme'))
        const { displayName: _, ...globex } = { ...realm('globex'), enabled: false }
        await adapter.realms.create(globex)
        same(await adapter.realms.find('acme'), realm('acme'), 'acme')
        same(await adapter.realms.find('globex'), globex, 'globex, which has no displayName')
        same((await adapter.realms.list()).map(found => found.id).sort(), ['acme', 'globex'], 'the realms listed')
        await adapter.realms.upsert({ ...realm('acme'), enabled: false, updatedAt: new Date(3_000) })
        same(await adapter.realms.find('acme'), { ...realm('acme'), enabled: false, updatedAt: new Date(3_000) }, 'acme after an upsert')
        await adapter.realms.destroy('acme')
        same(await adapter.realms.find('acme'), undefined, 'a destroyed realm')
        same(
          (await adapter.realms.list()).map(found => found.id),
          ['globex'],
          'the realms left'
        )
      }
    }
  ]
  return checks.filter(({ needs }) => !needs || claimed.has(needs)).map(({ name, run }) => ({ name, run }))
}
