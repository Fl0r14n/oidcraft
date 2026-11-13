import { describe, expect, test } from 'bun:test'
import { memoryAdapter } from '@oidcraft/adapter/memory'
import { addressBucket, createAccounts, generateSecretKey, hotp, type PasswordHasher } from './index'
import { open } from './sealed'
import { counterAt, fromBase32 } from './totp'

/** Fast and transparent: the hashing itself is the runtime entries' job, tested there. */
const hasher = (calls: string[] = [], delay = 0): PasswordHasher => ({
  async hash(password) {
    return `h:${password}`
  },
  async verify(password, hash) {
    calls.push(hash)
    if (delay) await Bun.sleep(delay)
    return hash === `h:${password}`
  }
})

const setup = async (calls: string[] = [], delay = 0) => {
  const adapter = await memoryAdapter()
  const secretKey = generateSecretKey()
  const accounts = createAccounts({
    adapter,
    hasher: hasher(calls, delay),
    secretKey,
    issuer: 'oidcraft test',
    newAccountId: username => `id-${username}`
  })
  return { adapter, accounts, secretKey }
}

const codeFor = (secret: string, offset = 0) => hotp(fromBase32(secret), counterAt(Date.now()) + offset)

describe('TOTP', () => {
  // RFC 6238 Appendix B, SHA-1, T = 59: 94287082 at eight digits, so 287082 at six.
  test('matches the RFC test vector', async () => {
    expect(await hotp(new TextEncoder().encode('12345678901234567890'), 1)).toBe('287082')
  })
})

describe('passwords', () => {
  test('a registered account signs in, by any spelling of its username', async () => {
    const { accounts } = await setup()
    expect(await accounts.register({ username: '  Ada ', password: 'correct horse' })).toEqual({ ok: true, accountId: 'id-ada' })
    expect(await accounts.authenticate('ADA', 'correct horse')).toEqual({ ok: true, accountId: 'id-ada', secondFactor: false })
    expect(await accounts.authenticate('ada', 'wrong horse')).toEqual({ ok: false, reason: 'invalid' })
  })

  test('a username is taken once, and a short password is refused', async () => {
    const { accounts } = await setup()
    await accounts.register({ username: 'ada', password: 'correct horse' })
    expect(await accounts.register({ username: 'Ada', password: 'another one' })).toEqual({ ok: false, reason: 'taken' })
    expect(await accounts.register({ username: 'grace', password: 'short' })).toEqual({
      ok: false,
      reason: 'password',
      problem: 'tooShort'
    })
    expect(await accounts.register({ username: ' ', password: 'long enough' })).toEqual({
      ok: false,
      reason: 'username',
      problem: 'required'
    })
  })

  test('an unknown username costs a verification too, so timing does not reveal it', async () => {
    const calls: string[] = []
    const { accounts } = await setup(calls)
    expect(await accounts.authenticate('nobody', 'whatever1')).toEqual({ ok: false, reason: 'invalid' })
    expect(calls).toHaveLength(1)
  })

  test('a locked account costs a verification too, so a quick answer does not reveal the username', async () => {
    const calls: string[] = []
    const { accounts } = await setup(calls)
    await accounts.register({ username: 'ada', password: 'correct horse' })
    for (let i = 0; i < 5; i++) await accounts.authenticate('ada', 'nope nope')
    const before = calls.length
    expect(await accounts.authenticate('ada', 'nope nope')).toMatchObject({ ok: false, reason: 'locked' })
    expect(calls.length).toBe(before + 1)
  })

  // G-9: a read-then-write count let 157 of 200 parallel guesses be checked before any of them was counted.
  for (const context of [{}, { clientIp: '203.0.113.6' }]) {
    test(`parallel guesses are counted before they are checked${context.clientIp ? ', per address' : ''}`, async () => {
      const calls: string[] = []
      const { accounts } = await setup(calls, 5)
      await accounts.register({ username: 'ada', password: 'correct horse' })
      const answers = await Promise.all(Array.from({ length: 200 }, () => accounts.authenticate('ada', 'nope nope', context)))
      expect(calls.filter(hash => hash === 'h:correct horse')).toHaveLength(5)
      expect(answers.filter(answer => answer.ok === false && answer.reason === 'locked')).toHaveLength(196)
      expect(await accounts.authenticate('ada', 'correct horse', context)).toMatchObject({ ok: false, reason: 'locked' })
    })
  }

  test('five failures lock the account, and the right password does not open it early', async () => {
    const { accounts } = await setup()
    await accounts.register({ username: 'ada', password: 'correct horse' })
    for (let i = 0; i < 4; i++) expect((await accounts.authenticate('ada', 'nope nope'))?.ok).toBe(false)
    expect(await accounts.authenticate('ada', 'nope nope')).toMatchObject({ ok: false, reason: 'locked' })
    expect(await accounts.authenticate('ada', 'correct horse')).toMatchObject({ ok: false, reason: 'locked' })
  })

  // G-9: someone guessing locks out their own address, not the account's owner.
  describe('with the peer address', () => {
    const at = (clientIp: string) => ({ clientIp })

    test('five failures lock that address out, and the owner elsewhere still signs in', async () => {
      const { accounts } = await setup()
      await accounts.register({ username: 'ada', password: 'correct horse' })
      for (let i = 0; i < 4; i++)
        expect(await accounts.authenticate('ada', 'nope nope', at('203.0.113.6'))).toEqual({ ok: false, reason: 'invalid' })
      expect(await accounts.authenticate('ada', 'nope nope', at('203.0.113.6'))).toMatchObject({ ok: false, reason: 'locked' })
      expect(await accounts.authenticate('ada', 'correct horse', at('203.0.113.6'))).toMatchObject({ ok: false, reason: 'locked' })
      expect(await accounts.authenticate('ada', 'correct horse', at('198.51.100.1'))).toMatchObject({ ok: true })
    })

    test('a guess spread over many addresses still locks the account for everyone', async () => {
      const { accounts } = await setup()
      await accounts.register({ username: 'ada', password: 'correct horse' })
      for (let address = 0; address < 25; address++) {
        for (let i = 0; i < 2; i++) await accounts.authenticate('ada', 'nope nope', at(`192.0.2.${address}`))
      }
      expect(await accounts.authenticate('ada', 'correct horse', at('198.51.100.1'))).toMatchObject({ ok: false, reason: 'locked' })
    })

    test('the owner signing in does not restart a guess spread over many addresses', async () => {
      const { accounts } = await setup()
      await accounts.register({ username: 'ada', password: 'correct horse' })
      for (let address = 0; address < 49; address++) await accounts.authenticate('ada', 'nope nope', at(`192.0.2.${address}`))
      expect(await accounts.authenticate('ada', 'correct horse', at('198.51.100.1'))).toMatchObject({ ok: true })
      expect(await accounts.authenticate('ada', 'nope nope', at('192.0.2.200'))).toMatchObject({ ok: false, reason: 'locked' })
    })

    test('an IPv6 guesser is counted by its /64, not address by address', async () => {
      const { accounts } = await setup()
      await accounts.register({ username: 'ada', password: 'correct horse' })
      for (let host = 1; host <= 4; host++) await accounts.authenticate('ada', 'nope nope', at(`2001:db8:1:2::${host}`))
      expect(await accounts.authenticate('ada', 'nope nope', at('2001:db8:1:2:ffff::9'))).toMatchObject({ ok: false, reason: 'locked' })
      expect(await accounts.authenticate('ada', 'correct horse', at('2001:db8:1:3::1'))).toMatchObject({ ok: true })
    })

    test('signing in clears that address’s count', async () => {
      const { accounts } = await setup()
      await accounts.register({ username: 'ada', password: 'correct horse' })
      for (let i = 0; i < 4; i++) await accounts.authenticate('ada', 'nope nope', at('203.0.113.6'))
      expect(await accounts.authenticate('ada', 'correct horse', at('203.0.113.6'))).toMatchObject({ ok: true })
      for (let i = 0; i < 4; i++)
        expect(await accounts.authenticate('ada', 'nope nope', at('203.0.113.6'))).toEqual({ ok: false, reason: 'invalid' })
      expect(await accounts.authenticate('ada', 'nope nope', at('203.0.113.6'))).toMatchObject({ ok: false, reason: 'locked' })
    })
  })

  test('released claims follow the scopes, and preferred_username is the username', async () => {
    const { accounts } = await setup()
    await accounts.register({ username: 'ada', password: 'correct horse', claims: { name: 'Ada', email: 'ada@example.test', secret: 'x' } })
    expect(await accounts.store.claims('id-ada', ['openid', 'profile'], [])).toEqual({ preferred_username: 'ada', name: 'Ada' })
    expect(await accounts.store.claims('id-ada', ['openid', 'email'], [])).toEqual({ email: 'ada@example.test' })
  })
})

describe('second factor', () => {
  const enrolled = async () => {
    const context = await setup()
    await context.accounts.register({ username: 'ada', password: 'correct horse' })
    const begun = await context.accounts.totp.begin('id-ada')
    if (!begun?.ok) throw new Error('enrolment did not begin')
    const confirmed = await context.accounts.totp.confirm('id-ada', await codeFor(begun.secret))
    if (!confirmed) throw new Error('enrolment did not confirm')
    return { ...context, secret: begun.secret, recoveryCodes: confirmed.recoveryCodes }
  }

  test('confirming enrolment issues recovery codes and makes sign-in ask for a code', async () => {
    const { accounts, recoveryCodes } = await enrolled()
    expect(recoveryCodes).toHaveLength(10)
    expect(await accounts.authenticate('ada', 'correct horse')).toEqual({ ok: true, accountId: 'id-ada', secondFactor: true })
    expect(await accounts.totp.status('id-ada')).toEqual({ enrolled: true, recoveryCodesLeft: 10 })
  })

  test('a code works once: the step that confirmed enrolment cannot sign in, the next one can, once', async () => {
    const { accounts, secret } = await enrolled()
    expect(await accounts.verifySecondFactor('id-ada', await codeFor(secret))).toEqual({ ok: false, reason: 'invalid' })
    const next = await codeFor(secret, 1)
    expect(await accounts.verifySecondFactor('id-ada', next)).toEqual({ ok: true, method: 'otp' })
    expect(await accounts.verifySecondFactor('id-ada', next)).toEqual({ ok: false, reason: 'invalid' })
  })

  test('a recovery code works once, in any spelling', async () => {
    const { accounts, recoveryCodes } = await enrolled()
    const code = recoveryCodes[0] as string
    expect(await accounts.verifySecondFactor('id-ada', ` ${code.toUpperCase().replace('-', '')} `)).toEqual({
      ok: true,
      method: 'recovery'
    })
    expect(await accounts.verifySecondFactor('id-ada', code)).toEqual({ ok: false, reason: 'invalid' })
    expect((await accounts.totp.status('id-ada')).recoveryCodesLeft).toBe(9)
  })

  // FR-I7: with the password known, a reset shared with it gave unlimited codes in rounds of four.
  test('a correct password does not reset the count of wrong codes', async () => {
    const { accounts } = await enrolled()
    for (let round = 0; round < 2; round++) {
      for (let i = 0; i < 2; i++) expect(await accounts.verifySecondFactor('id-ada', '000000')).toEqual({ ok: false, reason: 'invalid' })
      expect(await accounts.authenticate('ada', 'correct horse')).toMatchObject({ ok: true })
    }
    expect(await accounts.verifySecondFactor('id-ada', '000000')).toMatchObject({ ok: false, reason: 'locked' })
  })

  test('recovery codes are stored keyed, not as a hash anyone can recompute', async () => {
    const { adapter, recoveryCodes } = await enrolled()
    const stored = (await adapter.credentials?.find('id-ada'))?.recoveryCodes ?? []
    const plain = await crypto.subtle.digest('SHA-256', new TextEncoder().encode((recoveryCodes[0] as string).replace('-', '')))
    expect(stored).toHaveLength(10)
    expect(stored).not.toContain(Buffer.from(plain).toString('base64url'))
  })

  test('the stored secret is sealed to its account and opens nowhere else', async () => {
    const { adapter, secret, secretKey } = await enrolled()
    const stored = (await adapter.credentials?.find('id-ada'))?.totp?.secret as string
    expect(stored).not.toContain(secret)
    const key = await crypto.subtle.importKey('raw', Buffer.from(secretKey, 'base64url'), 'AES-GCM', false, ['decrypt'])
    expect(await open(key, 'id-ada', stored)).toEqual(fromBase32(secret))
    await expect(open(key, 'id-grace', stored)).rejects.toThrow()
  })

  test('enrolment cannot be restarted over a confirmed secret, only removed', async () => {
    const { accounts } = await enrolled()
    expect(await accounts.totp.begin('id-ada')).toEqual({ ok: false, reason: 'enrolled' })
    await accounts.totp.remove('id-ada')
    expect(await accounts.totp.status('id-ada')).toEqual({ enrolled: false, recoveryCodesLeft: 0 })
  })
})

describe('password reset', () => {
  // FR-T7: a reset is what someone does after a compromise, and an offline token that outlives it is the compromise continuing.
  test('revokes every token issued to the account and keeps its consents', async () => {
    const { adapter, accounts } = await setup()
    await accounts.register({ username: 'ada', password: 'correct horse' })
    const grant = { id: 'g1', accountId: 'id-ada', clientId: 'rp', scopes: ['openid'], claims: [], resources: {}, createdAt: new Date() }
    await adapter.grants.upsert(grant)
    await adapter.grants.upsert({ ...grant, id: 'g2', accountId: 'someone-else' })
    const token = { clientId: 'rp', payload: {}, expiresAt: new Date(Date.now() + 60_000) }
    await adapter.artifacts.upsert({ ...token, id: 'offline', kind: 'refresh_token', accountId: 'id-ada', grantId: 'g1' })
    await adapter.artifacts.upsert({ ...token, id: 'access', kind: 'access_token', accountId: 'id-ada', grantId: 'g1' })
    await adapter.artifacts.upsert({ ...token, id: 'theirs', kind: 'refresh_token', accountId: 'someone-else', grantId: 'g2' })

    const issued = await accounts.reset.issue('ada')
    await accounts.reset.complete(issued?.token as string, 'battery staple')

    expect(await adapter.artifacts.find('refresh_token', 'offline')).toBeUndefined()
    expect(await adapter.artifacts.find('access_token', 'access')).toBeUndefined()
    expect(await adapter.artifacts.find('refresh_token', 'theirs')).toBeDefined()
    expect(await adapter.grants.find('g1')).toBeDefined()
  })

  test('a token sets the password once and ends the sessions the old one opened', async () => {
    const { adapter, accounts } = await setup()
    await accounts.register({ username: 'ada', password: 'correct horse' })
    await adapter.sessions.upsert({
      id: 's1',
      accountId: 'id-ada',
      authTime: new Date(),
      clients: [],
      expiresAt: new Date(Date.now() + 60_000)
    })
    expect(await accounts.reset.issue('nobody')).toBeUndefined()
    const issued = await accounts.reset.issue('Ada')
    if (!issued) throw new Error('no token')
    expect(await accounts.reset.complete(issued.token, 'battery staple')).toEqual({ ok: true, accountId: 'id-ada' })
    expect(await adapter.sessions.find('s1')).toBeUndefined()
    expect((await accounts.authenticate('ada', 'battery staple')).ok).toBe(true)
    expect(await accounts.reset.complete(issued.token, 'another staple')).toEqual({ ok: false, reason: 'invalid' })
  })

  test('the token itself is not what is stored', async () => {
    const { adapter, accounts } = await setup()
    await accounts.register({ username: 'ada', password: 'correct horse' })
    const issued = await accounts.reset.issue('ada')
    expect(await adapter.artifacts.find('password_reset', issued?.token as string)).toBeUndefined()
  })
})

describe('addressBucket', () => {
  test('an IPv4 address is itself; an IPv6 one its /64, however it is written', () => {
    expect(addressBucket('192.0.2.7')).toBe('192.0.2.7')
    expect(addressBucket('2001:db8:1:2::9')).toBe('2001:db8:1:2::/64')
    expect(addressBucket('2001:0DB8:0001:0002:0000:0000:0000:0009')).toBe('2001:db8:1:2::/64')
    expect(addressBucket('[2001:db8::1]')).toBe('2001:db8:0:0::/64')
    expect(addressBucket('fe80::1%eth0')).toBe('fe80:0:0:0::/64')
    expect(addressBucket('::ffff:192.0.2.7')).toBe('192.0.2.7')
  })
})
