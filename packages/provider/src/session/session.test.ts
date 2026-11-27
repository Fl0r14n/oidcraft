import { afterEach, describe, expect, setSystemTime, test } from 'bun:test'
import type { EpochMillis, Session } from '@oidcraft/adapter'
import { storedId } from '../artifacts'
import type { Provider } from '../provider'
import { adapter, authorizeUrl, browserOf, build, ISSUER, useFlow } from '../test-flow'
import { isFresh } from './session'

const at = (authTime: EpochMillis): Session => ({
  id: 's',
  accountId: 'a',
  authTime,
  clients: [],
  expiresAt: authTime + 3_600_000
})

describe('isFresh', () => {
  afterEach(() => setSystemTime())

  // OIDC Core §3.1.2.1: max_age=0 is prompt=login, however recent the login. Measured as elapsed time it
  // passed whenever the login and the request fell in the same millisecond.
  test('max_age=0 is never fresh, even in the millisecond of the login', () => {
    const now = Date.parse('2026-11-11T12:00:00.000Z')
    setSystemTime(now)
    expect(isFresh(at(now), 0)).toBe(false)
  })

  // Re-authentication is required once the elapsed time is greater than max_age, not when it equals it.
  test('a session exactly max_age old is still fresh', () => {
    const now = Date.parse('2026-11-11T12:00:00.000Z')
    setSystemTime(now)
    expect(isFresh(at(now - 60_000), 60)).toBe(true)
    expect(isFresh(at(now - 60_001), 60)).toBe(false)
  })

  test('no max_age means any live session will do', () => {
    expect(isFresh(at(0), undefined)).toBe(true)
  })
})

describe('a sign-in in a browser that has a session (FR-I10)', () => {
  useFlow()
  afterEach(() => setSystemTime())

  /** Signs in as `accountId` with `prompt=login`, carrying `session` as the browser's cookie; answers the session cookie it set. */
  const signIn = async (on: Provider, accountId: string, session?: string) => {
    const first = await on.handle(new Request(authorizeUrl({ prompt: 'login' }), { headers: session ? { cookie: session } : {} }))
    const id = new URL(first.headers.get('location') as string).pathname.split('/').pop() as string
    const cookie = [browserOf(first), session].filter(Boolean).join('; ')
    const done = await on.interactions.complete(id, { login: { accountId } }, cookie)
    return (done.setCookie as string).split(';')[0] as string
  }
  const idOf = (pair: string) => (pair.split('=')[1] as string).split('.')[0] as string

  // S-1: the old session stayed in storage, unreachable by any logout, with every client it had signed in.
  test('another account ends the browser’s session first, as a logout does', async () => {
    const ended: string[] = []
    const on = build({ onSessionEnd: session => void ended.push(session.accountId) })
    const ada = await signIn(on, 'ada')
    await adapter.sessions.addClient(idOf(ada), 'rp')
    const bob = await signIn(on, 'bob', ada)
    expect(await adapter.sessions.find(idOf(ada))).toBeUndefined()
    expect(ended).toEqual(['ada'])
    expect((await adapter.sessions.find(idOf(bob)))?.accountId).toBe('bob')
  })

  test('the same account updates its session in place, its sid and clients kept, under a new secret', async () => {
    const on = build()
    setSystemTime(new Date('2026-11-27T10:00:00Z'))
    const first = await signIn(on, 'ada')
    await adapter.sessions.addClient(idOf(first), 'rp')
    setSystemTime(new Date('2026-11-27T11:00:00Z'))
    const again = await signIn(on, 'ada', first)
    expect(idOf(again)).toBe(idOf(first))
    expect(again).not.toBe(first)
    const session = await adapter.sessions.find(idOf(first))
    expect(session?.authTime).toBe(Date.parse('2026-11-27T11:00:00.000Z'))
    expect(session?.clients).toEqual(['rp'])
    expect((await on.session(new Request(ISSUER, { headers: { cookie: again } })))?.accountId).toBe('ada')
    // NFR-S11: a copy of the cookie from before gains nothing the later sign-in proved.
    expect(await on.session(new Request(ISSUER, { headers: { cookie: first } }))).toBeUndefined()
  })

  // NFR-S11: a cookie set before the id and secret were apart is the secret alone, and the session's id its hash.
  test('a session from before the split opens with its old cookie until the next sign-in replaces it', async () => {
    const on = build()
    const secret = 'an-old-secret-of-enough-length-to-pass-for-one'
    const id = await storedId(secret)
    await adapter.sessions.upsert({ id, accountId: 'ada', authTime: Date.now(), clients: ['rp'], expiresAt: Date.now() + 60_000 })
    const old = `__Host-oidcraft.sid=${secret}`
    expect((await on.session(new Request(ISSUER, { headers: { cookie: old } })))?.id).toBe(id)
    const again = await signIn(on, 'ada', old)
    expect(idOf(again)).toBe(id)
    expect(await on.session(new Request(ISSUER, { headers: { cookie: old } }))).toBeUndefined()
    expect((await on.session(new Request(ISSUER, { headers: { cookie: again } })))?.clients).toEqual(['rp'])
  })

  test('without an idle lifetime, a session unused for days is still there', async () => {
    const on = build()
    setSystemTime(new Date('2026-11-27T10:00:00Z'))
    const ada = await signIn(on, 'ada')
    setSystemTime(new Date('2026-11-30T10:00:00Z'))
    expect((await on.session(new Request(ISSUER, { headers: { cookie: ada } })))?.accountId).toBe('ada')
  })

  test('with an idle lifetime, a session ends that long after its last use, and each use moves it on', async () => {
    const on = build({ ttl: { sessionIdle: 600 } })
    setSystemTime(new Date('2026-11-27T10:00:00Z'))
    const ada = await signIn(on, 'ada')
    setSystemTime(new Date('2026-11-27T10:09:00Z'))
    await on.handle(new Request(authorizeUrl(), { headers: { cookie: ada } }))
    setSystemTime(new Date('2026-11-27T10:18:00Z'))
    expect((await on.session(new Request(ISSUER, { headers: { cookie: ada } })))?.accountId).toBe('ada')
    setSystemTime(new Date('2026-11-27T10:28:01Z'))
    expect(await on.session(new Request(ISSUER, { headers: { cookie: ada } }))).toBeUndefined()
    expect(await adapter.sessions.find(idOf(ada))).toBeUndefined()
  })
})
