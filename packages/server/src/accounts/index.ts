import { DEFAULT_MAX_LENGTH, oauthFieldError, randomString } from '@oidcraft/core'
import { base64url } from 'jose'
import type { AccountStore, Credential, CredentialsAdapter, Seconds } from 'oidcraft'
import { importSecretKey, open, seal } from './sealed'
import { base32, matchingCounter, otpauthUri, TOTP_PERIOD } from './totp'

export { generateSecretKey } from './sealed'
export { hotp } from './totp'

/** argon2id by default in the hashers the runtime entries ship; any PHC-string hasher fits. */
export type PasswordHasher = {
  hash(password: string): Promise<string>
  verify(password: string, hash: string): Promise<boolean>
}

export type AccountsPolicy = {
  /** NIST SP 800-63B §5.1.1.2. @default 8 */
  minPasswordLength: number
  /** Failed passwords or codes before the account locks. @default 5 */
  maxFailedAttempts: number
  /** @default 900 */
  lockout: Seconds
  /** How long a reset token lives. @default 1800 */
  resetTtl: Seconds
  /** @default 10 */
  recoveryCodes: number
}

export type AccountsOptions = {
  adapter: CredentialsAdapter
  hasher: PasswordHasher
  /** 32 random bytes, base64url, that seal TOTP secrets at rest. `generateSecretKey()` makes one. */
  secretKey: string
  /** The name an authenticator app shows beside the code. */
  issuer: string
  policy?: Partial<AccountsPolicy>
  /** scope → the stored claims it releases. @default OIDC Core §5.4's standard scopes */
  claims?: Record<string, string[]>
  /** @default a random id, so a username can change without changing the subject */
  newAccountId?: (username: string) => string
}

const STANDARD_CLAIMS: Record<string, string[]> = {
  profile: [
    'name',
    'family_name',
    'given_name',
    'middle_name',
    'nickname',
    'preferred_username',
    'profile',
    'picture',
    'website',
    'gender',
    'birthdate',
    'zoneinfo',
    'locale',
    'updated_at'
  ],
  email: ['email', 'email_verified'],
  address: ['address'],
  phone: ['phone_number', 'phone_number_verified']
}

export type AuthenticationResult =
  | { ok: true; accountId: string; secondFactor: boolean }
  | { ok: false; reason: 'invalid' }
  | { ok: false; reason: 'locked'; until: Date }

export type SecondFactorResult =
  | { ok: true; method: 'otp' | 'recovery' }
  | { ok: false; reason: 'invalid' }
  | { ok: false; reason: 'locked'; until: Date }

export type PasswordProblem = 'required' | 'tooShort' | 'tooLong'

export type RegistrationResult =
  | { ok: true; accountId: string }
  | { ok: false; reason: 'taken' }
  | { ok: false; reason: 'username'; problem: 'required' | 'tooLong' }
  | { ok: false; reason: 'password'; problem: PasswordProblem }

/** Usernames compare the way people read them: compatibility-normalized, trimmed, case-folded. */
export const normalizeUsername = (username: string) => username.normalize('NFKC').trim().toLowerCase()

const digest = async (value: string) =>
  base64url.encode(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))))

/** Ten base32 characters in two groups: about 50 bits, enough for a code that is also rate-limited. */
const recoveryCode = () => {
  const text = base32(crypto.getRandomValues(new Uint8Array(7)))
    .slice(0, 10)
    .toLowerCase()
  return `${text.slice(0, 5)}-${text.slice(5)}`
}

const normalizeRecoveryCode = (code: string) => code.trim().toLowerCase().replace(/[\s-]/g, '')

/** Long enough that a used recovery code cannot come back while it could still be on someone's paper. */
const RECOVERY_TOMBSTONE: Seconds = 10 * 365 * 24 * 3600

/**
 * Local accounts over the adapter's `credentials` store (FR-I7). The host decides which of these it
 * mounts: a deployment without sign-up simply never calls `register`.
 */
export const createAccounts = (options: AccountsOptions) => {
  const { credentials } = options.adapter
  const { adapter, hasher } = options
  const policy: AccountsPolicy = {
    minPasswordLength: 8,
    maxFailedAttempts: 5,
    lockout: 900,
    resetTtl: 1800,
    recoveryCodes: 10,
    ...options.policy
  }
  const scopes = options.claims ?? STANDARD_CLAIMS
  const key = importSecretKey(options.secretKey)
  // An unknown username still pays for one verification, so response time does not say which names exist.
  let decoy: Promise<string> | undefined
  const spendDecoy = (password: string) => {
    decoy ??= hasher.hash(randomString(32))
    return decoy.then(hash => hasher.verify(password, hash))
  }

  const passwordProblem = (password: string | undefined): PasswordProblem | undefined => {
    if (!password) return 'required'
    if (password.length < policy.minPasswordLength) return 'tooShort'
    if (password.length > DEFAULT_MAX_LENGTH) return 'tooLong'
    return undefined
  }

  const lockedUntil = (credential: Credential) =>
    credential.lockedUntil && credential.lockedUntil.getTime() > Date.now() ? credential.lockedUntil : undefined

  const fail = async (credential: Credential) => {
    const failedAttempts = credential.failedAttempts + 1
    const locking = failedAttempts >= policy.maxFailedAttempts
    const { lockedUntil: _, ...rest } = credential
    const until = new Date(Date.now() + policy.lockout * 1000)
    await credentials.upsert({
      ...rest,
      failedAttempts: locking ? 0 : failedAttempts,
      ...(locking && { lockedUntil: until }),
      updatedAt: new Date()
    })
    return locking ? ({ ok: false, reason: 'locked', until } as const) : ({ ok: false, reason: 'invalid' } as const)
  }

  const succeed = async (credential: Credential) => {
    if (credential.failedAttempts === 0 && !credential.lockedUntil) return
    const { lockedUntil: _, ...rest } = credential
    await credentials.upsert({ ...rest, failedAttempts: 0, updatedAt: new Date() })
  }

  const issueRecoveryCodes = async () => {
    const codes = Array.from({ length: policy.recoveryCodes }, recoveryCode)
    return { codes, hashes: await Promise.all(codes.map(code => digest(normalizeRecoveryCode(code)))) }
  }

  const store: AccountStore = {
    async find(accountId) {
      const credential = await credentials.find(accountId)
      return credential ? { accountId, claims: credential.claims } : undefined
    },
    async claims(accountId, requested) {
      const credential = await credentials.find(accountId)
      if (!credential) return undefined
      const all: Record<string, unknown> = { preferred_username: credential.username, ...credential.claims }
      const released = new Set(requested.flatMap(scope => scopes[scope] ?? []))
      return Object.fromEntries(Object.entries(all).filter(([name]) => released.has(name)))
    }
  }

  const setPassword = async (accountId: string, password: string) => {
    const problem = passwordProblem(password)
    if (problem) return { ok: false, problem } as const
    const credential = await credentials.find(accountId)
    if (!credential) return { ok: false, problem: 'unknown' } as const
    const { lockedUntil: _, ...rest } = credential
    await credentials.upsert({ ...rest, passwordHash: await hasher.hash(password), failedAttempts: 0, updatedAt: new Date() })
    return { ok: true } as const
  }

  return {
    /** Pass as the adapter's `accounts`: `createProvider({ adapter: { ...adapter, accounts: accounts.store } })`. */
    store,

    async register(input: { username: string; password: string; claims?: Record<string, unknown> }): Promise<RegistrationResult> {
      const username = normalizeUsername(input.username)
      const usernameProblem = oauthFieldError(username)
      if (usernameProblem) return { ok: false, reason: 'username', problem: usernameProblem }
      const problem = passwordProblem(input.password)
      if (problem) return { ok: false, reason: 'password', problem }
      const now = new Date()
      const accountId = options.newAccountId?.(username) ?? randomString(24)
      const created = await credentials.create({
        accountId,
        username,
        passwordHash: await hasher.hash(input.password),
        claims: input.claims ?? {},
        failedAttempts: 0,
        createdAt: now,
        updatedAt: now
      })
      return created ? { ok: true, accountId } : { ok: false, reason: 'taken' }
    },

    async authenticate(username: string, password: string): Promise<AuthenticationResult> {
      const credential = await credentials.findByUsername(normalizeUsername(username))
      if (!credential) {
        await spendDecoy(password)
        return { ok: false, reason: 'invalid' }
      }
      const until = lockedUntil(credential)
      if (until) return { ok: false, reason: 'locked', until }
      if (!(await hasher.verify(password, credential.passwordHash))) return fail(credential)
      await succeed(credential)
      return { ok: true, accountId: credential.accountId, secondFactor: Boolean(credential.totp?.confirmedAt) }
    },

    /** A TOTP code or a recovery code, each accepted once (NFR-S5). Failures count towards the lockout. */
    async verifySecondFactor(accountId: string, code: string): Promise<SecondFactorResult> {
      const credential = await credentials.find(accountId)
      if (!credential?.totp?.confirmedAt) return { ok: false, reason: 'invalid' }
      const until = lockedUntil(credential)
      if (until) return { ok: false, reason: 'locked', until }

      const counter = await matchingCounter(await open(await key, accountId, credential.totp.secret), code.replace(/\s/g, ''))
      if (counter !== undefined && (await adapter.replay.claim('totp', `${accountId}:${counter}`, 3 * TOTP_PERIOD))) {
        await succeed(credential)
        return { ok: true, method: 'otp' }
      }

      const hash = await digest(normalizeRecoveryCode(code))
      if (
        credential.recoveryCodes?.includes(hash) &&
        (await adapter.replay.claim('recovery', `${accountId}:${hash}`, RECOVERY_TOMBSTONE))
      ) {
        const { lockedUntil: _, ...rest } = credential
        await credentials.upsert({
          ...rest,
          recoveryCodes: credential.recoveryCodes.filter(stored => stored !== hash),
          failedAttempts: 0,
          updatedAt: new Date()
        })
        return { ok: true, method: 'recovery' }
      }

      return fail(credential)
    },

    setPassword,

    totp: {
      /** Starts enrolment. The secret only takes effect once `confirm` sees a code generated from it. */
      async begin(accountId: string) {
        const credential = await credentials.find(accountId)
        if (!credential) return undefined
        if (credential.totp?.confirmedAt) return { ok: false, reason: 'enrolled' } as const
        const secret = crypto.getRandomValues(new Uint8Array(20))
        await credentials.upsert({ ...credential, totp: { secret: await seal(await key, accountId, secret) }, updatedAt: new Date() })
        const encoded = base32(secret)
        return { ok: true, secret: encoded, uri: otpauthUri(encoded, options.issuer, credential.username) } as const
      },

      /** The first code proves the app holds the secret. Returns the recovery codes, shown once and stored hashed. */
      async confirm(accountId: string, code: string) {
        const credential = await credentials.find(accountId)
        if (!credential?.totp || credential.totp.confirmedAt) return undefined
        const counter = await matchingCounter(await open(await key, accountId, credential.totp.secret), code.replace(/\s/g, ''))
        if (counter === undefined || !(await adapter.replay.claim('totp', `${accountId}:${counter}`, 3 * TOTP_PERIOD))) return undefined
        const { codes, hashes } = await issueRecoveryCodes()
        await credentials.upsert({
          ...credential,
          totp: { secret: credential.totp.secret, confirmedAt: new Date() },
          recoveryCodes: hashes,
          updatedAt: new Date()
        })
        return { recoveryCodes: codes }
      },

      async remove(accountId: string) {
        const credential = await credentials.find(accountId)
        if (!credential) return
        const { totp: _, recoveryCodes: __, ...rest } = credential
        await credentials.upsert({ ...rest, updatedAt: new Date() })
      },

      async status(accountId: string) {
        const credential = await credentials.find(accountId)
        return {
          enrolled: Boolean(credential?.totp?.confirmedAt),
          recoveryCodesLeft: credential?.recoveryCodes?.length ?? 0
        }
      },

      /** Replaces every recovery code; the old ones stop working at once. */
      async regenerateRecoveryCodes(accountId: string) {
        const credential = await credentials.find(accountId)
        if (!credential?.totp?.confirmedAt) return undefined
        const { codes, hashes } = await issueRecoveryCodes()
        await credentials.upsert({ ...credential, recoveryCodes: hashes, updatedAt: new Date() })
        return { recoveryCodes: codes }
      }
    },

    reset: {
      /**
       * A single-use token for the host to deliver (FR-A1). Undefined for an unknown username: the
       * host must answer both the same way, or the form tells anyone which accounts exist.
       */
      async issue(username: string) {
        const credential = await credentials.findByUsername(normalizeUsername(username))
        if (!credential) return undefined
        const token = randomString(43)
        await adapter.artifacts.upsert({
          id: await digest(token),
          kind: 'password_reset',
          clientId: '',
          accountId: credential.accountId,
          payload: {},
          expiresAt: new Date(Date.now() + policy.resetTtl * 1000)
        })
        return { token, accountId: credential.accountId, claims: credential.claims }
      },

      /** Sets the new password and ends every session the old one opened. */
      async complete(token: string, password: string) {
        const problem = passwordProblem(password)
        if (problem) return { ok: false, reason: 'password', problem } as const
        const id = await digest(token)
        const artifact = await adapter.artifacts.find('password_reset', id)
        if (!artifact?.accountId || !(await adapter.artifacts.consume('password_reset', id)))
          return { ok: false, reason: 'invalid' } as const
        const set = await setPassword(artifact.accountId, password)
        if (!set.ok) return { ok: false, reason: 'invalid' } as const
        for (const session of await adapter.sessions.listForAccount(artifact.accountId)) await adapter.sessions.destroy(session.id)
        return { ok: true, accountId: artifact.accountId } as const
      }
    }
  }
}

export type Accounts = ReturnType<typeof createAccounts>
