import { DEFAULT_MAX_LENGTH, oauthFieldError, randomString } from '@oidcraft/core'
import type { AccountStore, Credential, CredentialsAdapter, Seconds } from '@oidcraft/provider'
import { base64url } from 'jose'
import { createPasskeys, displayNameOf, nameProblem, type PasskeyNameProblem, type RegistrationResponseJSON } from './passkeys'
import { importHashingKey, importSecretKey, open, seal } from './sealed'
import { base32, matchingCounter, otpauthUri, TOTP_PERIOD } from './totp'

export type {
  AuthenticationResponseJSON,
  PasskeyAuthenticationResult,
  PasskeyNameProblem,
  PasskeyRegistrationResult,
  PasskeyRemoval,
  PasskeySummary,
  RegistrationResponseJSON
} from './passkeys'
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
  /** Failures from one address before it is locked out of the account; without an address, before the account locks. @default 5 */
  maxFailedAttempts: number
  /** Failed attempts from all addresses together before the account locks for everyone (G-9). @default 50 */
  maxFailedAttemptsPerAccount: number
  /** How long the account-wide count of the attempt above remembers a failure. @default 86400 */
  failureWindow: Seconds
  /** @default 900 */
  lockout: Seconds
  /** How long a reset token lives. @default 1800 */
  resetTtl: Seconds
  /** @default 10 */
  recoveryCodes: number
  /** How long a passkey ceremony may take, a phone scanned for one included: WebAuthn L3 §15.1's upper bound (FR-I8). @default 600 */
  passkeyTimeout: Seconds
}

export type AccountsOptions = {
  adapter: CredentialsAdapter
  hasher: PasswordHasher
  /** 32 random bytes, base64url, that seal TOTP secrets at rest. `generateSecretKey()` makes one. */
  secretKey: string
  /** The name an authenticator app shows beside the code, and a passkey prompt shows for the site. */
  issuer: string
  /** The issuer's URL. Passkeys need it: their relying party ID is its host name, and an assertion must come from its origin (FR-I8). */
  origin?: string
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

/** The peer address from the runtime's context (FR-R4). With it a guesser locks out only their own address; else the account (G-9). */
export type SignInContext = { clientIp?: string | undefined }

type Attempts = { generation: string; lockedUntil?: number }

type Bucket = { scope: string; limit: number; ttl: Seconds }

/** IPv6 counts by its /64: one subscriber is routinely given a whole one, so by address a guesser has 2^64 of them (G-9). */
export const addressBucket = (ip: string) => {
  if (!ip.includes(':')) return ip
  const written = ip
    .toLowerCase()
    .replace(/^\[|\]$/g, '')
    .split('%')[0] as string
  const dotted = /^(.*:)(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(written)
  const [, lead = '', a = 0, b = 0, c = 0, d = 0] = dotted ?? []
  const address = dotted ? `${lead}${((+a << 8) | +b).toString(16)}:${((+c << 8) | +d).toString(16)}` : written
  const [head = '', tail] = address.split('::')
  const left = head ? head.split(':') : []
  const right = tail ? tail.split(':') : []
  const groups = tail === undefined ? left : [...left, ...Array<string>(Math.max(0, 8 - left.length - right.length)).fill('0'), ...right]
  const words = groups.map(group => Number.parseInt(group || '0', 16))
  const [w0, w1, w2, w3, w4, w5, w6 = 0, w7 = 0] = words
  // G-9: an IPv4 peer reached through a mapped address or a NAT64/SIIT translator (RFC 6052 §2.1) counts by its own address, not the translator's /64.
  if ((!w0 && !w1 && !w2 && !w3 && !w4 && w5 === 0xffff) || (w0 === 0x64 && w1 === 0xff9b && !w2 && !w3 && !w4 && !w5)) {
    return [w6 >> 8, w6 & 255, w7 >> 8, w7 & 255].join('.')
  }
  return `${words
    .slice(0, 4)
    .map(word => word.toString(16))
    .join(':')}::/64`
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

export type PasskeySignUpOptionsResult<Options> =
  | { ok: true; options: Options }
  | { ok: false; reason: 'taken' }
  | { ok: false; reason: 'username'; problem: 'required' | 'tooLong' }

export type PasskeySignUpResult =
  | { ok: true; accountId: string; recoveryCodes: string[] }
  | { ok: false; reason: 'invalid' | 'taken' }
  | { ok: false; reason: 'name'; problem: PasskeyNameProblem }

export type RecoveryResult =
  | { ok: true; accountId: string; token: string }
  | { ok: false; reason: 'invalid' }
  | { ok: false; reason: 'locked'; until: Date }

export type PasskeyResetResult =
  | { ok: true; accountId: string }
  | { ok: false; reason: 'invalid' | 'taken' }
  | { ok: false; reason: 'name'; problem: PasskeyNameProblem }

export type RegistrationResult =
  | { ok: true; accountId: string }
  | { ok: false; reason: 'taken' }
  | { ok: false; reason: 'username'; problem: 'required' | 'tooLong' }
  | { ok: false; reason: 'password'; problem: PasswordProblem }

/** Usernames compare the way people read them: compatibility-normalized, trimmed, case-folded. */
export const normalizeUsername = (username: string) => username.normalize('NFKC').trim().toLowerCase()

const digest = async (value: string) =>
  base64url.encode(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))))

const SLOTS = 'sign_in'

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

/** Local accounts over the adapter's `credentials` store (FR-I7); a host without sign-up never calls `register`. */
export const createAccounts = (options: AccountsOptions) => {
  const { credentials } = options.adapter
  const { adapter, hasher } = options
  const policy: AccountsPolicy = {
    minPasswordLength: 8,
    maxFailedAttempts: 5,
    maxFailedAttemptsPerAccount: 50,
    failureWindow: 86_400,
    lockout: 900,
    resetTtl: 1800,
    recoveryCodes: 10,
    passkeyTimeout: 600,
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

  const attemptsAt = async (scope: string) => (await adapter.artifacts.find('sign_in_attempts', scope))?.payload as Attempts | undefined
  const lockedAt = async (scope: string) => {
    const until = (await attemptsAt(scope))?.lockedUntil
    return until && until > Date.now() ? new Date(until) : undefined
  }

  /** Every address together, never reset by a good sign-in: otherwise the owner signing in would restart a spread-out guess (G-9). */
  const accountWide = (accountId: string): Bucket => ({
    scope: `${accountId}:*`,
    limit: policy.maxFailedAttemptsPerAccount,
    ttl: policy.failureWindow
  })
  /** This address, or the account when there is none (G-9); a second factor's apart, so a known password does not reset it. */
  const ownBucket = (accountId: string, factor: 'password' | 'code', context: SignInContext): Bucket => ({
    scope: `${accountId}:${factor === 'code' ? 'code:' : ''}${context.clientIp ? addressBucket(context.clientIp) : '-'}`,
    limit: policy.maxFailedAttempts,
    ttl: policy.lockout
  })

  const lockFor = async (credential: Credential, bucket: Bucket) =>
    lockedUntil(credential) ?? (await lockedAt(accountWide(credential.accountId).scope)) ?? (await lockedAt(bucket.scope))

  /** Kept as long as a slot of the new generation can live. */
  const renew = async (bucket: Bucket, accountId: string, lockUntil?: Date) =>
    adapter.artifacts.upsert({
      id: bucket.scope,
      kind: 'sign_in_attempts',
      clientId: '',
      accountId,
      payload: { generation: randomString(8), ...(lockUntil && { lockedUntil: lockUntil.getTime() }) } satisfies Attempts,
      expiresAt: new Date((lockUntil?.getTime() ?? Date.now()) + bucket.ttl * 1000)
    })

  /** Atomic: a read-then-write count lets parallel guesses all pass a check none of them has yet failed (G-9). */
  const claimSlot = async (bucket: Bucket) => {
    const generation = (await attemptsAt(bucket.scope))?.generation ?? '0'
    for (let slot = 0; slot < bucket.limit; slot++) {
      if (await adapter.replay.claim(SLOTS, `${bucket.scope}:${generation}:${slot}`, bucket.ttl)) return slot
    }
    return undefined
  }

  const locked = (until: Date) => ({ ok: false, reason: 'locked', until }) as const
  const invalid = { ok: false, reason: 'invalid' } as const
  const lockoutFromNow = () => new Date(Date.now() + policy.lockout * 1000)

  /** Before the slow verify, so at most `limit` guesses run at once; a locked account still pays one hash, or names leak (FR-I7). */
  const admit = async (credential: Credential, bucket: Bucket, password?: string) => {
    const lockedFor = await lockFor(credential, bucket)
    const slot = lockedFor ? undefined : await claimSlot(bucket)
    if (slot === undefined) {
      if (password !== undefined) await spendDecoy(password)
      return { refused: locked(lockedFor ?? lockoutFromNow()) }
    }
    return { slot }
  }

  const fail = async (accountId: string, bucket: Bucket, slot: number, context: SignInContext) => {
    const until = lockoutFromNow()
    if (context.clientIp) {
      const wide = accountWide(accountId)
      const counted = await claimSlot(wide)
      if (counted === undefined || counted === wide.limit - 1) {
        await renew(wide, accountId, until)
        return locked(until)
      }
    }
    if (slot < bucket.limit - 1) return invalid
    await renew(bucket, accountId, until)
    return locked(until)
  }

  /** Only a bucket someone failed in this generation is renewed, so a clean sign-in writes nothing. */
  const succeed = async (accountId: string, bucket: Bucket, slot: number) => {
    if (slot > 0) await renew(bucket, accountId)
  }

  const hashingKey = importHashingKey(options.secretKey)
  /** Keyed and bound to the account: 50 bits unsalted are a dictionary away from a dump (FR-I7). */
  const recoveryHash = async (accountId: string, code: string) =>
    base64url.encode(
      new Uint8Array(
        await crypto.subtle.sign('HMAC', await hashingKey, new TextEncoder().encode(`${accountId}:${normalizeRecoveryCode(code)}`))
      )
    )

  const { creationOptions, verifyCreation, keep, ...passkeys } = createPasskeys({
    adapter,
    origin: options.origin,
    name: options.issuer,
    hashingKey,
    ttl: policy.passkeyTimeout
  })

  const issueRecoveryCodes = async (accountId: string) => {
    const codes = Array.from({ length: policy.recoveryCodes }, recoveryCode)
    return { codes, hashes: await Promise.all(codes.map(code => recoveryHash(accountId, code))) }
  }

  /** Spends one of the account's recovery codes, once (NFR-S5). */
  const redeemRecoveryCode = async (credential: Credential, code: string) => {
    const { accountId } = credential
    const hash = await recoveryHash(accountId, code)
    if (
      !credential.recoveryCodes?.includes(hash) ||
      !(await adapter.replay.claim('recovery', `${accountId}:${hash}`, RECOVERY_TOMBSTONE))
    ) {
      return false
    }
    // Read again after the claim: written from the copy read before, a reset or TOTP change in between would be undone.
    const current = await credentials.find(accountId)
    if (current) {
      await credentials.upsert({
        ...current,
        recoveryCodes: (current.recoveryCodes ?? []).filter(stored => stored !== hash),
        updatedAt: new Date()
      })
    }
    return true
  }

  const issueResetToken = async (accountId: string) => {
    const token = randomString(43)
    await adapter.artifacts.upsert({
      id: await digest(token),
      kind: 'password_reset',
      clientId: '',
      accountId,
      payload: {},
      expiresAt: new Date(Date.now() + policy.resetTtl * 1000)
    })
    return token
  }

  /** What a reset finishes with, whichever credential it set: the old ones' sessions end and their tokens are revoked (FR-T7). */
  const afterReset = async (accountId: string, context: SignInContext) => {
    // G-9: guesses at a password that is gone lock nothing; a fresh generation, so no slot of the old one counts.
    const buckets = [accountWide(accountId), ownBucket(accountId, 'password', {}), ownBucket(accountId, 'code', {})]
    if (context.clientIp) buckets.push(ownBucket(accountId, 'password', context), ownBucket(accountId, 'code', context))
    for (const bucket of buckets) await renew(bucket, accountId)
    for (const session of await adapter.sessions.listForAccount(accountId)) await adapter.sessions.destroy(session.id)
    // FR-T7: an offline refresh token carries its own sign-in and would outlive the sessions. The consent stays, under a
    // new id, so a token a racing refresh writes after the sweep names a grant that is gone (FR-T3).
    for (const grant of await adapter.grants.listForAccount(accountId)) {
      await adapter.grants.destroy(grant.id)
      await adapter.artifacts.revokeByGrantId(grant.id)
      await adapter.grants.merge({ ...grant, id: randomString() })
    }
  }

  const signUpBinding = (interactionId: string) => `sign-up:${interactionId}`
  const resetBinding = (tokenDigest: string) => `reset:${tokenDigest}`

  const passkeySignUp = {
    /**
     * Creation options for a new account that will have this passkey and no password (FR-I8), bound to the interaction. The
     * username is checked here so the person hears it is taken before their authenticator is asked; `signUp` checks again.
     */
    async signUpOptions(interactionId: string, input: { username: string; claims?: Record<string, unknown> }) {
      const username = normalizeUsername(input.username)
      const problem = oauthFieldError(username)
      if (problem) return { ok: false, reason: 'username', problem } as const
      if (await credentials.findByUsername(username)) return { ok: false, reason: 'taken' } as const
      const claims = input.claims ?? {}
      const accountId = options.newAccountId?.(username) ?? randomString(24)
      const created = await creationOptions(
        { accountId, username, displayName: displayNameOf(username, claims) },
        { ceremony: 'create', binding: signUpBinding(interactionId), signUp: { username, claims } }
      )
      return { ok: true, options: created } as const
    },

    /** Creates the account `signUpOptions` described, with this passkey and no password. Its recovery codes are in the answer, to show once. */
    async signUp(interactionId: string, response: RegistrationResponseJSON, label: string): Promise<PasskeySignUpResult> {
      const passkeyName = label.trim()
      const problem = nameProblem(passkeyName)
      if (problem) return { ok: false, reason: 'name', problem }
      const created = await verifyCreation(response, { ceremony: 'create', binding: signUpBinding(interactionId) })
      if (!created?.signUp) return invalid
      const { accountId, signUp } = created
      const { codes, hashes } = await issueRecoveryCodes(accountId)
      const now = new Date()
      const account = { accountId, ...signUp, recoveryCodes: hashes, failedAttempts: 0, createdAt: now, updatedAt: now }
      if (!(await credentials.create(account))) return { ok: false, reason: 'taken' }
      // FR-I8: an account with neither a password nor a passkey has no way in, so it does not stay.
      if (!(await keep(created.passkey(passkeyName))).ok) {
        await credentials.destroy(accountId)
        return invalid
      }
      return { ok: true, accountId, recoveryCodes: codes }
    }
  }

  const store: AccountStore = {
    async find(accountId) {
      const credential = await credentials.find(accountId)
      return credential ? { accountId, claims: credential.claims } : undefined
    },
    async claims(accountId, requested, named) {
      const credential = await credentials.find(accountId)
      if (!credential) return undefined
      const all: Record<string, unknown> = { preferred_username: credential.username, ...credential.claims }
      const released = new Set([...requested.flatMap(scope => scopes[scope] ?? []), ...named])
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

    async authenticate(username: string, password: string, context: SignInContext = {}): Promise<AuthenticationResult> {
      const credential = await credentials.findByUsername(normalizeUsername(username))
      if (!credential?.passwordHash) {
        await spendDecoy(password)
        return invalid
      }
      const { passwordHash } = credential
      const bucket = ownBucket(credential.accountId, 'password', context)
      const admitted = await admit(credential, bucket, password)
      if (admitted.refused) return admitted.refused
      if (!(await hasher.verify(password, passwordHash))) return fail(credential.accountId, bucket, admitted.slot, context)
      await succeed(credential.accountId, bucket, admitted.slot)
      return { ok: true, accountId: credential.accountId, secondFactor: Boolean(credential.totp?.confirmedAt) }
    },

    /** A TOTP code or a recovery code, each accepted once (NFR-S5). Failures count towards the lockout. */
    async verifySecondFactor(accountId: string, code: string, context: SignInContext = {}): Promise<SecondFactorResult> {
      const credential = await credentials.find(accountId)
      if (!credential?.totp?.confirmedAt) return invalid
      const bucket = ownBucket(accountId, 'code', context)
      const admitted = await admit(credential, bucket)
      if (admitted.refused) return admitted.refused

      const counter = await matchingCounter(await open(await key, accountId, credential.totp.secret), code.replace(/\s/g, ''))
      if (counter !== undefined && (await adapter.replay.claim('totp', `${accountId}:${counter}`, 3 * TOTP_PERIOD))) {
        await succeed(accountId, bucket, admitted.slot)
        return { ok: true, method: 'otp' }
      }

      if (await redeemRecoveryCode(credential, code)) {
        await succeed(accountId, bucket, admitted.slot)
        return { ok: true, method: 'recovery' }
      }

      return fail(accountId, bucket, admitted.slot, context)
    },

    /**
     * A recovery code in place of the lost passkey of an account with no password (FR-I8). It spends the code and answers a
     * reset token, for `reset.completeWithPasskey` or `reset.complete`; it signs no one in.
     */
    async recover(username: string, code: string, context: SignInContext = {}): Promise<RecoveryResult> {
      const credential = await credentials.findByUsername(normalizeUsername(username))
      // G-9: every answer pays one hash, as a password's does, so how long it takes names no account.
      if (!credential || credential.passwordHash) {
        await spendDecoy(code)
        return invalid
      }
      const { accountId } = credential
      const bucket = ownBucket(accountId, 'code', context)
      const admitted = await admit(credential, bucket, code)
      if (admitted.refused) return admitted.refused
      const [redeemed] = await Promise.all([redeemRecoveryCode(credential, code), spendDecoy(code)])
      if (!redeemed) return fail(accountId, bucket, admitted.slot, context)
      await succeed(accountId, bucket, admitted.slot)
      return { ok: true, accountId, token: await issueResetToken(accountId) }
    },

    /** Replaces every recovery code; the old ones stop working at once. For an account with TOTP, or with no password. */
    async regenerateRecoveryCodes(accountId: string) {
      const credential = await credentials.find(accountId)
      if (!credential || (credential.passwordHash && !credential.totp?.confirmedAt)) return undefined
      const { codes, hashes } = await issueRecoveryCodes(accountId)
      await credentials.upsert({ ...credential, recoveryCodes: hashes, updatedAt: new Date() })
      return { recoveryCodes: codes }
    },

    setPassword,

    /** WebAuthn: a sign-in of its own, by autofill, or a second factor beside TOTP; and an account's only credential (FR-I8). */
    passkeys: { ...passkeys, ...passkeySignUp },

    totp: {
      /** Starts enrolment. The secret only takes effect once `confirm` sees a code generated from it. */
      async begin(accountId: string) {
        const credential = await credentials.find(accountId)
        if (!credential) return undefined
        if (credential.totp?.confirmedAt) return { ok: false, reason: 'enrolled' } as const
        // A second factor follows a password; an account without one signs in with a passkey, already two (FR-I8).
        if (!credential.passwordHash) return { ok: false, reason: 'passwordless' } as const
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
        const { codes, hashes } = await issueRecoveryCodes(accountId)
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
      }
    },

    reset: {
      /** A single-use token for the host to deliver (FR-A1); undefined for an unknown username, which the host must answer identically. */
      async issue(username: string) {
        const credential = await credentials.findByUsername(normalizeUsername(username))
        if (!credential) return undefined
        return { token: await issueResetToken(credential.accountId), accountId: credential.accountId, claims: credential.claims }
      },

      /** The same, for an administrator to send someone who lost every way in. Who may ask is the host's decision (FR-M1). */
      async issueForAccount(accountId: string) {
        const credential = await credentials.find(accountId)
        if (!credential) return undefined
        return { token: await issueResetToken(accountId), accountId, claims: credential.claims }
      },

      /** Creation options for a new passkey in place of the password, or of a lost passkey; undefined for a token that is not live. */
      async passkeyOptions(token: string) {
        const id = await digest(token)
        const artifact = await adapter.artifacts.find('password_reset', id)
        const credential = artifact?.accountId && !artifact.consumedAt ? await credentials.find(artifact.accountId) : undefined
        if (!credential) return undefined
        const { accountId, username, claims } = credential
        return creationOptions(
          { accountId, username, displayName: displayNameOf(username, claims) },
          { ceremony: 'create', binding: resetBinding(id) }
        )
      },

      /** Adds the passkey made from `passkeyOptions`, spends the token and, as `complete` does, ends what the old credentials opened. */
      async completeWithPasskey(
        token: string,
        response: RegistrationResponseJSON,
        label: string,
        context: SignInContext = {}
      ): Promise<PasskeyResetResult> {
        const passkeyName = label.trim()
        const problem = nameProblem(passkeyName)
        if (problem) return { ok: false, reason: 'name', problem }
        const id = await digest(token)
        const created = await verifyCreation(response, { ceremony: 'create', binding: resetBinding(id) })
        if (!created) return invalid
        const artifact = await adapter.artifacts.find('password_reset', id)
        if (artifact?.accountId !== created.accountId || !(await adapter.artifacts.consume('password_reset', id))) return invalid
        const kept = await keep(created.passkey(passkeyName))
        if (!kept.ok) return { ok: false, reason: 'taken' }
        await afterReset(created.accountId, context)
        return { ok: true, accountId: created.accountId }
      },

      /** Sets the new password, ends every session the old one opened and revokes the tokens issued to the account (FR-T7). */
      async complete(token: string, password: string, context: SignInContext = {}) {
        const problem = passwordProblem(password)
        if (problem) return { ok: false, reason: 'password', problem } as const
        const id = await digest(token)
        const artifact = await adapter.artifacts.find('password_reset', id)
        if (!artifact?.accountId || !(await adapter.artifacts.consume('password_reset', id)))
          return { ok: false, reason: 'invalid' } as const
        const set = await setPassword(artifact.accountId, password)
        if (!set.ok) return { ok: false, reason: 'invalid' } as const
        await afterReset(artifact.accountId, context)
        return { ok: true, accountId: artifact.accountId } as const
      }
    }
  }
}

export type Accounts = ReturnType<typeof createAccounts>
