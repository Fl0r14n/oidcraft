import { DEFAULT_MAX_LENGTH, oauthFieldError, randomString } from '@oidcraft/core'
import { type BrokeringAdapter, type CredentialsAdapter, type Expiring, type Seconds, toPlainAdapter } from '@oidcraft/provider'
import { base64url } from 'jose'

/** argon2id by default in the hashers the runtime entries ship; any PHC-string hasher fits. */
export type PasswordHasher = {
  hash(password: string): Promise<string>
  verify(password: string, hash: string): Promise<boolean>
}

export type AccountsPolicy = {
  /** NIST SP 800-63B-4 §3.1.1.2, for a password used alone (FR-I7). @default 15 */
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
  /** How long an email sign-in token lives, never past its interaction (FR-I9.1). @default 900 */
  emailSignInTtl: Seconds
  /** Email sign-in tokens issued to one address within `emailSignInWindow` (NFR-S12). @default 5 */
  emailSignInsPerAddress: number
  /** @default 3600 */
  emailSignInWindow: Seconds
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
  /**
   * @default a random id, so a username can change without changing the subject. One id names one account: sign-up refuses
   * an id that already has linked identities, so a username chosen to read `google:<sub>` takes no one's account (FR-I7, FR-F5).
   */
  newAccountId?: (username: string) => string
  /** A blocklist, which no dependency-free library can ship (NFR-D4): true refuses the password as `rejected` (FR-I7). */
  rejectPassword?: (password: string, account: { username: string }) => boolean | Promise<boolean>
}

/** The peer address from the runtime's context (FR-R4). With it a guesser locks out only their own address; else the account (G-9). */
export type SignInContext = { clientIp?: string | undefined }

export type PasswordProblem = 'required' | 'tooShort' | 'tooLong' | 'rejected'

/** RFC 8265 §3.3, UsernameCaseMapped: width-mapped by NFKC, trimmed, case-mapped, then NFC, so it compares as people read it. */
export const normalizeUsername = (username: string) => username.normalize('NFKC').trim().toLowerCase().normalize('NFC')

// RFC 8264 §4.2's IdentifierClass, closely: letters, marks and digits of any script, and printable ASCII, never a space,
// a control or format character, or a symbol that renders like another.
const IDENTIFIER = /^[\p{L}\p{M}\p{Nd}\x21-\x7E]+$/u

export type UsernameProblem = 'required' | 'tooLong' | 'invalid'

/** A normalised username's problem, if it has one. */
export const usernameProblem = (username: string): UsernameProblem | undefined =>
  oauthFieldError(username) ?? (IDENTIFIER.test(username) ? undefined : 'invalid')

export const digest = async (value: string) =>
  base64url.encode(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))))

export const invalid = { ok: false, reason: 'invalid' } as const

export const locked = (lock: Expiring) => ({ ok: false, reason: 'locked', lock }) as const

/** A lock while it lasts: the host's suspension of a credential (FR-I7), or the throttle's (G-9). */
export const liveLock = (lock: Expiring | undefined) => (lock && lock.expiresAt > Date.now() ? lock : undefined)

const DEFAULT_POLICY: AccountsPolicy = {
  minPasswordLength: 15,
  maxFailedAttempts: 5,
  maxFailedAttemptsPerAccount: 50,
  failureWindow: 86_400,
  lockout: 900,
  resetTtl: 1800,
  recoveryCodes: 10,
  passkeyTimeout: 600,
  emailSignInTtl: 900,
  emailSignInsPerAddress: 5,
  emailSignInWindow: 3600
}

/** What every part of the accounts entry reads: the adapter, the policy with its defaults, and the rules more than one applies. */
export const createShared = (options: AccountsOptions) => {
  const { hasher } = options
  // A1: a class-based adapter keeps its prototype methods however the stores below are passed around.
  const adapter = toPlainAdapter(options.adapter)
  const policy: AccountsPolicy = { ...DEFAULT_POLICY, ...options.policy }
  // An unknown username still pays for one verification, so response time does not say which names exist.
  let decoy: Promise<string> | undefined
  return {
    options,
    adapter,
    credentials: adapter.credentials,
    hasher,
    policy,
    newAccountId: (username: string) => options.newAccountId?.(username) ?? randomString(24),
    spendDecoy(password: string) {
      decoy ??= hasher.hash(randomString(32))
      return decoy.then(hash => hasher.verify(password, hash))
    },
    async passwordProblem(password: string | undefined, username: string): Promise<PasswordProblem | undefined> {
      if (!password) return 'required'
      if (password.length < policy.minPasswordLength) return 'tooShort'
      if (password.length > DEFAULT_MAX_LENGTH) return 'tooLong'
      if (await options.rejectPassword?.(password, { username })) return 'rejected'
      return undefined
    },
    /** FR-I7, FR-F5: one id names one account, so an id an upstream's identities already name is taken. */
    async linkedElsewhere(accountId: string) {
      return Boolean((await (adapter as Partial<BrokeringAdapter>).identities?.listForAccount(accountId))?.length)
    }
  }
}

/** `lock` is the host's suspension: kept, so a new password does not lift it (FR-I7). */
export const passwordSetter =
  ({ credentials, hasher, passwordProblem }: ReturnType<typeof createShared>) =>
  async (accountId: string, password: string) => {
    const credential = await credentials.find(accountId)
    const problem = await passwordProblem(password, credential?.username ?? '')
    if (problem) return { ok: false, reason: 'password', problem } as const
    if (!credential) return { ok: false, reason: 'unknown' } as const
    await credentials.update(accountId, { passwordHash: await hasher.hash(password), failedAttempts: 0, updatedAt: Date.now() })
    return { ok: true } as const
  }

export type Shared = ReturnType<typeof createShared>
