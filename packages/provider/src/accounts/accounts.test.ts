import { describe, expect, test } from 'bun:test'
import { memoryAdapter } from '../adapters/memory'
import { createAccounts, generateSecretKey, hotp, type PasswordHasher } from './index'
import { open } from './sealed'
import { counterAt, fromBase32 } from './totp'

/** Fast and transparent: the hashing itself is the runtime entries' job, tested there. */
const hasher = (calls: string[] = []): PasswordHasher => ({
  async hash(password) {
    return `h:${password}`
  },
  async verify(password, hash) {
    calls.push(hash)
    return hash === `h:${password}`
  }
})

const setup = async (calls: string[] = []) => {
  const adapter = await memoryAdapter()
  const secretKey = generateSecretKey()
  const accounts = createAccounts({
    adapter,
    hasher: hasher(calls),
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

  test('five failures lock the account, and the right password does not open it early', async () => {
    const { accounts } = await setup()
    await accounts.register({ username: 'ada', password: 'correct horse' })
    for (let i = 0; i < 4; i++) expect((await accounts.authenticate('ada', 'nope nope'))?.ok).toBe(false)
    expect(await accounts.authenticate('ada', 'nope nope')).toMatchObject({ ok: false, reason: 'locked' })
    expect(await accounts.authenticate('ada', 'correct horse')).toMatchObject({ ok: false, reason: 'locked' })
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
