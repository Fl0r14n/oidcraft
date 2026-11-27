import { describe, expect, test } from 'bun:test'
import { memoryAdapter } from '@oidcraft/adapter/memory'
import { addressBucket, createAccounts, generateSecretKey, hotp, type PasswordHasher } from './index'
import { createSealer } from './sealed'
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
    newAccountId: username => `id-${username}`,
    // The fixtures' passwords predate the 15-character default, which its own test covers.
    policy: { minPasswordLength: 8 }
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
  test('a signed-up account signs in, by any spelling of its username', async () => {
    const { accounts } = await setup()
    expect(await accounts.signUp({ username: '  Ada ', password: 'correct horse' })).toEqual({ ok: true, accountId: 'id-ada' })
    expect(await accounts.authenticate('ADA', 'correct horse')).toEqual({ ok: true, accountId: 'id-ada', secondFactor: false })
    expect(await accounts.authenticate('ada', 'wrong horse')).toEqual({ ok: false, reason: 'invalid' })
  })

  // §9.3: a refusal names its reason, and a field rule's problem beside it.
  test('setting a password refuses a weak one, or an account that is not there, by reason', async () => {
    const { accounts } = await setup()
    await accounts.signUp({ username: 'ada', password: 'correct horse' })
    expect(await accounts.setPassword('id-ada', 'short')).toEqual({ ok: false, reason: 'password', problem: 'tooShort' })
    expect(await accounts.setPassword('nobody', 'long enough')).toEqual({ ok: false, reason: 'unknown' })
    expect(await accounts.setPassword('id-ada', 'long enough')).toEqual({ ok: true })
  })

  test('a username is taken once, and a short password is refused', async () => {
    const { accounts } = await setup()
    await accounts.signUp({ username: 'ada', password: 'correct horse' })
    expect(await accounts.signUp({ username: 'Ada', password: 'another one' })).toEqual({ ok: false, reason: 'taken' })
    expect(await accounts.signUp({ username: 'grace', password: 'short' })).toEqual({
      ok: false,
      reason: 'password',
      problem: 'tooShort'
    })
    expect(await accounts.signUp({ username: ' ', password: 'long enough' })).toEqual({
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
    await accounts.signUp({ username: 'ada', password: 'correct horse' })
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
      await accounts.signUp({ username: 'ada', password: 'correct horse' })
      const answers = await Promise.all(Array.from({ length: 200 }, () => accounts.authenticate('ada', 'nope nope', context)))
      expect(calls.filter(hash => hash === 'h:correct horse')).toHaveLength(5)
      expect(answers.filter(answer => answer.ok === false && answer.reason === 'locked')).toHaveLength(196)
      expect(await accounts.authenticate('ada', 'correct horse', context)).toMatchObject({ ok: false, reason: 'locked' })
    })
  }

  test('five failures lock the account, and the right password does not open it early', async () => {
    const { accounts } = await setup()
    await accounts.signUp({ username: 'ada', password: 'correct horse' })
    for (let i = 0; i < 4; i++) expect((await accounts.authenticate('ada', 'nope nope'))?.ok).toBe(false)
    expect(await accounts.authenticate('ada', 'nope nope')).toMatchObject({ ok: false, reason: 'locked' })
    expect(await accounts.authenticate('ada', 'correct horse')).toMatchObject({ ok: false, reason: 'locked' })
  })

  // G-9: someone guessing locks out their own address, not the account's owner.
  describe('with the peer address', () => {
    const at = (clientIp: string) => ({ clientIp })

    test('five failures lock that address out, and the owner elsewhere still signs in', async () => {
      const { accounts } = await setup()
      await accounts.signUp({ username: 'ada', password: 'correct horse' })
      for (let i = 0; i < 4; i++)
        expect(await accounts.authenticate('ada', 'nope nope', at('203.0.113.6'))).toEqual({ ok: false, reason: 'invalid' })
      expect(await accounts.authenticate('ada', 'nope nope', at('203.0.113.6'))).toMatchObject({ ok: false, reason: 'locked' })
      expect(await accounts.authenticate('ada', 'correct horse', at('203.0.113.6'))).toMatchObject({ ok: false, reason: 'locked' })
      expect(await accounts.authenticate('ada', 'correct horse', at('198.51.100.1'))).toMatchObject({ ok: true })
    })

    test('a guess spread over many addresses still locks the account for everyone', async () => {
      const { accounts } = await setup()
      await accounts.signUp({ username: 'ada', password: 'correct horse' })
      for (let address = 0; address < 25; address++) {
        for (let i = 0; i < 2; i++) await accounts.authenticate('ada', 'nope nope', at(`192.0.2.${address}`))
      }
      expect(await accounts.authenticate('ada', 'correct horse', at('198.51.100.1'))).toMatchObject({ ok: false, reason: 'locked' })
    })

    test('the owner signing in does not restart a guess spread over many addresses', async () => {
      const { accounts } = await setup()
      await accounts.signUp({ username: 'ada', password: 'correct horse' })
      for (let address = 0; address < 49; address++) await accounts.authenticate('ada', 'nope nope', at(`192.0.2.${address}`))
      expect(await accounts.authenticate('ada', 'correct horse', at('198.51.100.1'))).toMatchObject({ ok: true })
      expect(await accounts.authenticate('ada', 'nope nope', at('192.0.2.200'))).toMatchObject({ ok: false, reason: 'locked' })
    })

    test('an IPv6 guesser is counted by its /64, not address by address', async () => {
      const { accounts } = await setup()
      await accounts.signUp({ username: 'ada', password: 'correct horse' })
      for (let host = 1; host <= 4; host++) await accounts.authenticate('ada', 'nope nope', at(`2001:db8:1:2::${host}`))
      expect(await accounts.authenticate('ada', 'nope nope', at('2001:db8:1:2:ffff::9'))).toMatchObject({ ok: false, reason: 'locked' })
      expect(await accounts.authenticate('ada', 'correct horse', at('2001:db8:1:3::1'))).toMatchObject({ ok: true })
    })

    test('signing in clears that address’s count', async () => {
      const { accounts } = await setup()
      await accounts.signUp({ username: 'ada', password: 'correct horse' })
      for (let i = 0; i < 4; i++) await accounts.authenticate('ada', 'nope nope', at('203.0.113.6'))
      expect(await accounts.authenticate('ada', 'correct horse', at('203.0.113.6'))).toMatchObject({ ok: true })
      for (let i = 0; i < 4; i++)
        expect(await accounts.authenticate('ada', 'nope nope', at('203.0.113.6'))).toEqual({ ok: false, reason: 'invalid' })
      expect(await accounts.authenticate('ada', 'nope nope', at('203.0.113.6'))).toMatchObject({ ok: false, reason: 'locked' })
    })
  })

  // A-1, G-9: a fresh generation on the lock freed all fifty slots, so a spread-out guess got fifty more every lockout.
  test('the account-wide count outlives its lock: past it, one more spread-out guess locks again', async () => {
    const { adapter, accounts } = await setup()
    await accounts.signUp({ username: 'ada', password: 'correct horse' })
    for (let address = 0; address < 50; address++) await accounts.authenticate('ada', 'nope nope', { clientIp: `192.0.2.${address}` })
    const wide = await adapter.artifacts.find('sign_in_attempts', 'id-ada:*')
    if (!wide) throw new Error('no account-wide count')
    await adapter.artifacts.upsert({ ...wide, payload: { ...wide.payload, lock: { expiresAt: Date.now() - 1 } } })
    expect(await accounts.authenticate('ada', 'nope nope', { clientIp: '192.0.2.100' })).toMatchObject({ ok: false, reason: 'locked' })
  })

  // NFR-D6: a lock written as `lockedUntil`, before `lock`, outlives the deploy that renamed it.
  test('a lock stored as lockedUntil still holds', async () => {
    const { adapter, accounts } = await setup()
    await accounts.signUp({ username: 'ada', password: 'correct horse' })
    for (let address = 0; address < 50; address++) await accounts.authenticate('ada', 'nope nope', { clientIp: `192.0.2.${address}` })
    const wide = await adapter.artifacts.find('sign_in_attempts', 'id-ada:*')
    if (!wide) throw new Error('no account-wide count')
    const { lock, ...rest } = wide.payload as { lock: { expiresAt: number } }
    await adapter.artifacts.upsert({ ...wide, payload: { ...rest, lockedUntil: lock.expiresAt } })
    expect(await accounts.authenticate('ada', 'correct horse', { clientIp: '192.0.2.200' })).toMatchObject({
      ok: false,
      reason: 'locked',
      lock
    })
  })

  // A-8, G-9: an unknown username that never locked told a guesser which names exist.
  test('an unknown username, or one no password signs in to, locks as a known one does', async () => {
    const { accounts } = await setup()
    await accounts.signUp({ username: 'ada', password: 'correct horse' })
    for (const username of ['ada', 'nobody']) {
      for (let i = 0; i < 4; i++) expect(await accounts.authenticate(username, 'nope nope')).toEqual({ ok: false, reason: 'invalid' })
      expect(await accounts.authenticate(username, 'nope nope')).toMatchObject({ ok: false, reason: 'locked' })
    }
    for (let i = 0; i < 4; i++) expect(await accounts.recover('ada', 'aaaaa-bbbbb')).toEqual({ ok: false, reason: 'invalid' })
    expect(await accounts.recover('ada', 'aaaaa-bbbbb')).toMatchObject({ ok: false, reason: 'locked' })
  })

  // FR-I7: NIST SP 800-63B-4 §3.1.1.2 asks fifteen of a password used alone; the blocklist is the host's.
  test('the default minimum is fifteen, the maximum holds at sign-in, and the host may reject a password', async () => {
    const calls: string[] = []
    const accounts = createAccounts({
      adapter: await memoryAdapter(),
      hasher: hasher(calls),
      secretKey: generateSecretKey(),
      issuer: 'oidcraft test',
      rejectPassword: (password, { username }) => password.includes(username) || password === 'password password'
    })
    expect(accounts.policy.minPasswordLength).toBe(15)
    expect(await accounts.signUp({ username: 'ada', password: 'fourteen chars' })).toMatchObject({ problem: 'tooShort' })
    expect(await accounts.signUp({ username: 'ada', password: 'password password' })).toMatchObject({ problem: 'rejected' })
    expect(await accounts.signUp({ username: 'ada', password: 'ada is my password' })).toMatchObject({ problem: 'rejected' })
    expect(await accounts.signUp({ username: 'ada', password: 'fifteen chars!!' })).toMatchObject({ ok: true })
    calls.length = 0
    expect(await accounts.authenticate('ada', 'x'.repeat(129))).toEqual({ ok: false, reason: 'invalid' })
    expect(calls).toHaveLength(1)
    expect(calls[0]).not.toContain('x'.repeat(129))
  })

  // A-9, FR-I7: `lock` is the host's suspension, which nothing in the library lifts.
  test('a new password, or a reset, leaves the host’s suspension in place', async () => {
    const { adapter, accounts } = await setup()
    await accounts.signUp({ username: 'ada', password: 'correct horse' })
    const credential = await adapter.credentials.find('id-ada')
    const suspended = { expiresAt: Date.now() + 3_600_000 }
    await adapter.credentials.upsert({ ...(credential as NonNullable<typeof credential>), lock: suspended })
    await accounts.setPassword('id-ada', 'battery staple')
    const issued = await accounts.reset.issue('ada')
    await accounts.reset.complete(issued?.token as string, 'another staple')
    expect((await adapter.credentials.find('id-ada'))?.lock).toEqual(suspended)
    expect(await accounts.authenticate('ada', 'another staple')).toMatchObject({ ok: false, reason: 'locked' })
  })

  // A-6: setPassword wrote back the whole row it read before hashing, undoing whatever landed in between.
  test('a write landing while a password is set is kept', async () => {
    const adapter = await memoryAdapter()
    const suspended = { expiresAt: Date.now() + 3_600_000 }
    let during: (() => Promise<unknown>) | undefined
    const accounts = createAccounts({
      adapter,
      hasher: {
        async hash(password) {
          await during?.()
          return `h:${password}`
        },
        async verify(password, hash) {
          return hash === `h:${password}`
        }
      },
      secretKey: generateSecretKey(),
      issuer: 'oidcraft test',
      newAccountId: username => `id-${username}`,
      policy: { minPasswordLength: 8 }
    })
    await accounts.signUp({ username: 'ada', password: 'correct horse' })
    during = () => adapter.credentials.update('id-ada', { lock: suspended })
    expect(await accounts.setPassword('id-ada', 'battery staple')).toEqual({ ok: true })
    const credential = await adapter.credentials.find('id-ada')
    expect(credential?.lock).toEqual(suspended)
    expect(credential?.passwordHash).toBe('h:battery staple')
  })

  // RFC 8265 §3.3: a username compares as people read it, and holds nothing that reads as something else.
  test('usernames are RFC 8265 identifiers, compared as people read them', async () => {
    const { accounts } = await setup()
    expect(await accounts.signUp({ username: 'ＡＤＡ', password: 'correct horse' })).toEqual({ ok: true, accountId: 'id-ada' })
    expect(await accounts.signUp({ username: 'ada', password: 'correct horse' })).toEqual({ ok: false, reason: 'taken' })
    expect((await accounts.signUp({ username: 'A\u0301da', password: 'correct horse' })).ok).toBe(true)
    expect(await accounts.authenticate('\u00c1DA', 'correct horse')).toMatchObject({ ok: true })
    for (const username of ['ada lovelace', 'ada\u200b', 'ada\u0007', 'ada\u2028x']) {
      expect(await accounts.signUp({ username, password: 'correct horse' })).toEqual({ ok: false, reason: 'username', problem: 'invalid' })
    }
    expect((await accounts.signUp({ username: 'grace.hopper+navy@example.com', password: 'correct horse' })).ok).toBe(true)
  })

  // Q9, FR-I7: a username chosen to read as `google:<sub>` must not become that person's account.
  test('sign-up refuses an id that linked identities already name', async () => {
    const { adapter, accounts } = await setup()
    await adapter.identities.upsert({ upstream: 'google', subject: '1', accountId: 'id-google:1', claims: {}, createdAt: Date.now() })
    expect(await accounts.signUp({ username: 'google:1', password: 'correct horse' })).toEqual({ ok: false, reason: 'taken' })
    expect(await adapter.credentials.find('id-google:1')).toBeUndefined()
  })

  test('released claims follow the scopes, and preferred_username is the username', async () => {
    const { accounts } = await setup()
    await accounts.signUp({ username: 'ada', password: 'correct horse', claims: { name: 'Ada', email: 'ada@example.test', secret: 'x' } })
    expect(await accounts.store.claims('id-ada', ['openid', 'profile'], [])).toEqual({ preferred_username: 'ada', name: 'Ada' })
    expect(await accounts.store.claims('id-ada', ['openid', 'email'], [])).toEqual({ email: 'ada@example.test' })
  })
})

describe('second factor', () => {
  const enrolled = async () => {
    const context = await setup()
    await context.accounts.signUp({ username: 'ada', password: 'correct horse' })
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
    const sealer = await createSealer(secretKey)
    expect(await sealer.open('id-ada', stored)).toEqual(fromBase32(secret))
    await expect(sealer.open('id-grace', stored)).rejects.toThrow()
  })

  // A key derived for sealing alone, named in what it sealed: a secret sealed under another key says so.
  test('a secret is sealed under a derived key it names, and one under another key is refused as such', async () => {
    const { adapter, secretKey } = await enrolled()
    const stored = (await adapter.credentials?.find('id-ada'))?.totp?.secret as string
    const sealer = await createSealer(secretKey)
    expect(stored.split('.').slice(0, 2)).toEqual(['v2', sealer.kid])
    const raw = await crypto.subtle.importKey('raw', Buffer.from(secretKey, 'base64url'), 'AES-GCM', false, ['decrypt'])
    const [, , iv, ciphertext] = stored.split('.') as string[]
    const additionalData = new TextEncoder().encode('id-ada')
    await expect(
      crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: Buffer.from(iv as string, 'base64url'), additionalData },
        raw,
        Buffer.from(ciphertext as string, 'base64url')
      )
    ).rejects.toThrow()
    await expect((await createSealer(generateSecretKey())).open('id-ada', stored)).rejects.toThrow(/sealed under key/)
  })

  test('a secret sealed in the old format, under the secret itself, is still read', async () => {
    const secretKey = generateSecretKey()
    const raw = await crypto.subtle.importKey('raw', Buffer.from(secretKey, 'base64url'), 'AES-GCM', false, ['encrypt'])
    const iv = crypto.getRandomValues(new Uint8Array(12))
    const additionalData = new TextEncoder().encode('id-ada')
    const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData }, raw, new Uint8Array([1, 2, 3])))
    const v1 = `v1.${Buffer.from(iv).toString('base64url')}.${Buffer.from(sealed).toString('base64url')}`
    expect(await (await createSealer(secretKey)).open('id-ada', v1)).toEqual(new Uint8Array([1, 2, 3]))
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
    await accounts.signUp({ username: 'ada', password: 'correct horse' })
    const grant = { id: 'g1', accountId: 'id-ada', clientId: 'rp', scopes: ['openid'], claims: [], resources: {}, createdAt: Date.now() }
    await adapter.grants.upsert(grant)
    await adapter.grants.upsert({ ...grant, id: 'g2', accountId: 'someone-else' })
    const token = { clientId: 'rp', payload: {}, expiresAt: Date.now() + 60_000 }
    await adapter.artifacts.upsert({ ...token, id: 'offline', kind: 'refresh_token', accountId: 'id-ada', grantId: 'g1' })
    await adapter.artifacts.upsert({ ...token, id: 'access', kind: 'access_token', accountId: 'id-ada', grantId: 'g1' })
    await adapter.artifacts.upsert({ ...token, id: 'theirs', kind: 'refresh_token', accountId: 'someone-else', grantId: 'g2' })

    const issued = await accounts.reset.issue('ada')
    await accounts.reset.complete(issued?.token as string, 'battery staple')

    expect(await adapter.artifacts.find('refresh_token', 'offline')).toBeUndefined()
    expect(await adapter.artifacts.find('access_token', 'access')).toBeUndefined()
    expect(await adapter.artifacts.find('refresh_token', 'theirs')).toBeDefined()
    // The consent stays, under a new id: a token a racing refresh writes into g1 after the sweep finds its grant gone.
    const kept = await adapter.grants.findByAccountAndClient('id-ada', 'rp')
    expect(kept?.scopes).toEqual(['openid'])
    expect(kept?.id).not.toBe('g1')
    expect(await adapter.grants.find('g1')).toBeUndefined()
  })

  test('a token sets the password once and ends the sessions the old one opened', async () => {
    const { adapter, accounts } = await setup()
    await accounts.signUp({ username: 'ada', password: 'correct horse' })
    await adapter.sessions.upsert({
      id: 's1',
      accountId: 'id-ada',
      authTime: Date.now(),
      clients: [],
      expiresAt: Date.now() + 60_000
    })
    expect(await accounts.reset.issue('nobody')).toBeUndefined()
    const issued = await accounts.reset.issue('Ada')
    if (!issued) throw new Error('no token')
    expect(await accounts.reset.complete(issued.token, 'battery staple')).toEqual({ ok: true, accountId: 'id-ada' })
    expect(await adapter.sessions.find('s1')).toBeUndefined()
    expect((await accounts.authenticate('ada', 'battery staple')).ok).toBe(true)
    expect(await accounts.reset.complete(issued.token, 'another staple')).toEqual({ ok: false, reason: 'invalid' })
  })

  // G-9: the lock was against guesses at a password the reset just replaced.
  test('lifts the locks, account-wide and of the address completing it', async () => {
    const { accounts } = await setup()
    await accounts.signUp({ username: 'ada', password: 'correct horse' })
    for (let address = 0; address < 50; address++) await accounts.authenticate('ada', 'nope nope', { clientIp: `192.0.2.${address}` })
    for (let i = 0; i < 5; i++) await accounts.authenticate('ada', 'nope nope', { clientIp: '198.51.100.1' })
    for (let i = 0; i < 5; i++) await accounts.authenticate('ada', 'nope nope')
    expect(await accounts.authenticate('ada', 'correct horse', { clientIp: '198.51.100.1' })).toMatchObject({ reason: 'locked' })

    const issued = await accounts.reset.issue('ada')
    await accounts.reset.complete(issued?.token as string, 'battery staple', { clientIp: '198.51.100.1' })
    expect(await accounts.authenticate('ada', 'battery staple', { clientIp: '198.51.100.1' })).toMatchObject({ ok: true })
    expect(await accounts.authenticate('ada', 'battery staple', { clientIp: '203.0.113.9' })).toMatchObject({ ok: true })
    expect(await accounts.authenticate('ada', 'battery staple')).toMatchObject({ ok: true })
  })

  // A-5, FR-I7: a second link sent to a mailbox someone else read is spent by the reset too.
  test('completing a reset spends every other reset and email sign-in token of the account', async () => {
    const { accounts } = await setup()
    await accounts.signUp({
      username: 'ada@example.test',
      password: 'correct horse',
      claims: { email: 'ada@example.test', email_verified: true }
    })
    const first = await accounts.reset.issue('ada@example.test')
    const second = await accounts.reset.issue('ada@example.test')
    const email = await accounts.emailSignIn.issue('ada@example.test', {
      id: 'i-1',
      clientId: 'rp',
      expiresAt: Date.now() + 600_000
    })
    if (!first || !second) throw new Error('no token')
    if (!email.ok) throw new Error(email.reason)
    expect(await accounts.reset.complete(first.token, 'battery staple')).toMatchObject({ ok: true })
    expect(await accounts.emailSignIn.find(email.token)).toBeUndefined()
    expect(await accounts.emailSignIn.redeem(email.token)).toEqual({ ok: false, reason: 'invalid' })
    expect(await accounts.reset.complete(second.token, 'another staple')).toEqual({ ok: false, reason: 'invalid' })
    expect(await accounts.reset.passkeyOptions(second.token)).toBeUndefined()
    const after = await accounts.reset.issue('ada@example.test')
    expect(await accounts.reset.complete(after?.token as string, 'another staple')).toMatchObject({ ok: true })
  })

  test('the token itself is not what is stored', async () => {
    const { adapter, accounts } = await setup()
    await accounts.signUp({ username: 'ada', password: 'correct horse' })
    const issued = await accounts.reset.issue('ada')
    expect(await adapter.artifacts.find('password_reset', issued?.token as string)).toBeUndefined()
  })
})

describe('email sign-in (FR-I9)', () => {
  const interaction = (expiresAt = Date.now() + 1_800_000) => ({ id: 'i-1', clientId: 'rp', expiresAt })
  const verified = { email: 'ada@example.com', email_verified: true }

  test('an address with no account signs up and in, proven, only where the host offers sign-up', async () => {
    const { accounts } = await setup()
    expect(await accounts.emailSignIn.issue('Ada@Example.com', interaction())).toEqual({
      ok: false,
      reason: 'unknown',
      address: 'ada@example.com'
    })
    const issued = await accounts.emailSignIn.issue(' Ada@Example.com', interaction(), { signUp: { claims: { name: 'Ada' } } })
    if (!issued.ok) throw new Error('not issued')
    expect(issued.accountId).toBeUndefined()
    expect(await accounts.emailSignIn.find(issued.token)).toEqual({ address: 'ada@example.com', interactionId: 'i-1' })
    expect(await accounts.emailSignIn.redeem(issued.token)).toEqual({
      ok: true,
      accountId: 'id-ada@example.com',
      interactionId: 'i-1',
      secondFactor: false,
      signedUp: true
    })
    expect(await accounts.store.claims('id-ada@example.com', ['email', 'profile'], [])).toMatchObject({
      name: 'Ada',
      email: 'ada@example.com',
      email_verified: true
    })
    const again = await accounts.emailSignIn.issue('ada@example.com', interaction())
    expect(again).toMatchObject({ ok: true, accountId: 'id-ada@example.com' })
  })

  test('a token is spent once, by the POST, and only an address-shaped address is issued one', async () => {
    const { accounts } = await setup()
    const issued = await accounts.emailSignIn.issue('ada@example.com', interaction(), { signUp: {} })
    if (!issued.ok) throw new Error('not issued')
    expect(await accounts.emailSignIn.find(issued.token)).toEqual({ address: 'ada@example.com', interactionId: 'i-1' })
    expect(await accounts.emailSignIn.find(issued.token)).toEqual({ address: 'ada@example.com', interactionId: 'i-1' })
    expect((await accounts.emailSignIn.redeem(issued.token)).ok).toBe(true)
    expect(await accounts.emailSignIn.redeem(issued.token)).toEqual({ ok: false, reason: 'invalid' })
    expect(await accounts.emailSignIn.find(issued.token)).toBeUndefined()
    expect(await accounts.emailSignIn.redeem('made-up')).toEqual({ ok: false, reason: 'invalid' })
    for (const [address, problem] of [
      ['', 'required'],
      ['ada', 'invalid'],
      ['ada@', 'invalid'],
      ['a da@example.com', 'invalid']
    ] as const) {
      expect(await accounts.emailSignIn.issue(address, interaction(), { signUp: {} })).toEqual({
        ok: false,
        reason: 'address',
        problem
      })
    }
  })

  test('a token outlives its interaction by nothing', async () => {
    const { accounts } = await setup()
    const issued = await accounts.emailSignIn.issue('ada@example.com', interaction(Date.now() - 1000), { signUp: {} })
    if (!issued.ok) throw new Error('not issued')
    expect(await accounts.emailSignIn.find(issued.token)).toBeUndefined()
    expect(await accounts.emailSignIn.redeem(issued.token)).toEqual({ ok: false, reason: 'invalid' })
  })

  const passkeyFor = (accountId: string) => ({
    accountId,
    credentialId: `c-${accountId}`,
    publicKey: 'spki',
    algorithm: -7,
    counter: 0,
    transports: [],
    name: 'phone',
    createdAt: Date.now()
  })

  // FR-I9: the inbox would be a silent way around the phishing resistance the owner chose.
  test('an account with a passkey is never signed in by email, and the host hears why', async () => {
    const { accounts, adapter } = await setup()
    const issued = await accounts.emailSignIn.issue('ada@example.com', interaction(), { signUp: {} })
    if (!issued.ok) throw new Error('not issued')
    expect((await accounts.emailSignIn.redeem(issued.token)).ok).toBe(true)
    await adapter.passkeys.create(passkeyFor('id-ada@example.com'))
    expect(await accounts.emailSignIn.issue('ada@example.com', interaction(), { signUp: {} })).toEqual({
      ok: false,
      reason: 'passkey',
      address: 'ada@example.com'
    })
  })

  test('a token issued before a passkey was added does not sign in after', async () => {
    const { accounts, adapter } = await setup()
    await accounts.signUp({ username: 'ada@example.com', password: 'correct horse', claims: verified })
    const issued = await accounts.emailSignIn.issue('ada@example.com', interaction())
    if (!issued.ok) throw new Error('not issued')
    await adapter.passkeys.create(passkeyFor('id-ada@example.com'))
    expect(await accounts.emailSignIn.redeem(issued.token)).toEqual({ ok: false, reason: 'passkey' })
  })

  // Pre-hijacking: whoever signed up with someone else's address would keep their password beside the owner's inbox.
  test('an account with a password signs in by email only once that address was proven on it', async () => {
    const { accounts } = await setup()
    await accounts.signUp({ username: 'ada@example.com', password: 'correct horse' })
    expect(await accounts.emailSignIn.issue('ada@example.com', interaction(), { signUp: {} })).toEqual({
      ok: false,
      reason: 'unverified',
      address: 'ada@example.com'
    })
    await accounts.signUp({ username: 'bob@example.com', password: 'correct horse', claims: { ...verified, email: 'other@example.com' } })
    expect(await accounts.emailSignIn.issue('bob@example.com', interaction())).toMatchObject({ ok: false, reason: 'unverified' })

    await accounts.signUp({ username: 'cy@example.com', password: 'correct horse', claims: { ...verified, email: 'Cy@Example.com' } })
    const issued = await accounts.emailSignIn.issue('cy@example.com', interaction())
    if (!issued.ok) throw new Error('not issued')
    expect(await accounts.emailSignIn.redeem(issued.token)).toMatchObject({ ok: true, accountId: 'id-cy@example.com', signedUp: false })
  })

  test('a sign-up that lost the race to a password sign-up signs nobody in', async () => {
    const { accounts } = await setup()
    const issued = await accounts.emailSignIn.issue('ada@example.com', interaction(), { signUp: {} })
    if (!issued.ok) throw new Error('not issued')
    await accounts.signUp({ username: 'ada@example.com', password: 'correct horse' })
    expect(await accounts.emailSignIn.redeem(issued.token)).toEqual({ ok: false, reason: 'invalid' })
  })

  test('the inbox is a first factor: an account with TOTP is still asked for a code', async () => {
    const { accounts } = await setup()
    await accounts.signUp({ username: 'ada@example.com', password: 'correct horse', claims: verified })
    const begun = await accounts.totp.begin('id-ada@example.com')
    if (!begun?.ok) throw new Error('enrolment did not begin')
    await accounts.totp.confirm('id-ada@example.com', await codeFor(begun.secret))
    const issued = await accounts.emailSignIn.issue('ada@example.com', interaction())
    if (!issued.ok) throw new Error('not issued')
    expect(await accounts.emailSignIn.redeem(issued.token)).toMatchObject({ ok: true, secondFactor: true })
  })

  // NFR-S12: counted per address whether or not an account has it, so the count names no account either.
  test('tokens are capped per address, for an address with no account as for one with', async () => {
    const { accounts } = await setup()
    for (let sent = 0; sent < 5; sent++) {
      expect(await accounts.emailSignIn.issue('nobody@example.com', interaction())).toMatchObject({ reason: 'unknown' })
    }
    expect(await accounts.emailSignIn.issue('NOBODY@example.com', interaction(), { signUp: {} })).toMatchObject({
      ok: false,
      reason: 'locked'
    })
    expect((await accounts.emailSignIn.issue('somebody@example.com', interaction(), { signUp: {} })).ok).toBe(true)
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

  // A translator puts every IPv4 peer in one /64, so counting by it would let one guesser lock out all of them.
  test('an IPv4 peer behind NAT64 or a mapped address is its own IPv4 address', () => {
    expect(addressBucket('64:ff9b::192.0.2.7')).toBe('192.0.2.7')
    expect(addressBucket('64:ff9b::c000:207')).toBe('192.0.2.7')
    expect(addressBucket('64:ff9b::198.51.100.1')).not.toBe(addressBucket('64:ff9b::192.0.2.7'))
    expect(addressBucket('::ffff:c000:207')).toBe('192.0.2.7')
    expect(addressBucket('64:ff9b:1::c000:207')).toBe('64:ff9b:1:0::/64')
  })
})
