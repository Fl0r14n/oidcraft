import { afterEach, describe, expect, setSystemTime, test } from 'bun:test'
import type { Session } from '@oidcraft/adapter'
import { isFresh } from './session'

const at = (authTime: Date): Session => ({
  id: 's',
  accountId: 'a',
  authTime,
  clients: [],
  expiresAt: new Date(authTime.getTime() + 3_600_000)
})

describe('isFresh', () => {
  afterEach(() => setSystemTime())

  // OIDC Core §3.1.2.1: max_age=0 is prompt=login, however recent the login. Measured as elapsed time it
  // passed whenever the login and the request fell in the same millisecond.
  test('max_age=0 is never fresh, even in the millisecond of the login', () => {
    const now = new Date('2026-11-11T12:00:00.000Z')
    setSystemTime(now)
    expect(isFresh(at(now), 0)).toBe(false)
  })

  // Re-authentication is required once the elapsed time is greater than max_age, not when it equals it.
  test('a session exactly max_age old is still fresh', () => {
    const now = new Date('2026-11-11T12:00:00.000Z')
    setSystemTime(now)
    expect(isFresh(at(new Date(now.getTime() - 60_000)), 60)).toBe(true)
    expect(isFresh(at(new Date(now.getTime() - 60_001)), 60)).toBe(false)
  })

  test('no max_age means any live session will do', () => {
    expect(isFresh(at(new Date(0)), undefined)).toBe(true)
  })
})
