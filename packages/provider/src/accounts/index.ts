import { DEFAULT_MAX_LENGTH, oauthFieldError } from '@oidcraft/core'
import type { AccountStore } from '@oidcraft/provider'
import { createEmailSignIn } from './email'
import { createTotpEnrolment } from './enrolment'
import { createPasskeys, displayNameOf, nameProblem, type PasskeyNameProblem, type RegistrationResponseJSON } from './passkeys'
import { createRecovery } from './recovery'
import { createReset } from './reset'
import { importHashingKey, importSecretKey, open } from './sealed'
import {
  type AccountsOptions,
  createShared,
  invalid,
  lockedUntil,
  normalizeUsername,
  type PasswordProblem,
  passwordSetter,
  type SignInContext
} from './shared'
import { createThrottle } from './throttle'
import { matchingCounter, TOTP_PERIOD } from './totp'

export type { AddressProblem, EmailSignInInteraction, EmailSignInIssue, EmailSignInResult } from './email'
export type {
  AuthenticationResponseJSON,
  PasskeyAuthenticationResult,
  PasskeyNameProblem,
  PasskeyRegistrationResult,
  PasskeyRemoval,
  PasskeySummary,
  RegistrationResponseJSON
} from './passkeys'
export type { PasskeyResetResult } from './reset'
export { generateSecretKey } from './sealed'
export {
  type AccountsOptions,
  type AccountsPolicy,
  normalizeUsername,
  type PasswordHasher,
  type PasswordProblem,
  type SignInContext
} from './shared'
export { addressBucket } from './throttle'
export { hotp } from './totp'

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

export type SignUpResult =
  | { ok: true; accountId: string }
  | { ok: false; reason: 'taken' }
  | { ok: false; reason: 'username'; problem: 'required' | 'tooLong' }
  | { ok: false; reason: 'password'; problem: PasswordProblem }

const signUpBinding = (interactionId: string) => `sign-up:${interactionId}`

/** Local accounts over the adapter's `credentials` store (FR-I7); a host without sign-up never mounts `signUp`. */
export const createAccounts = (options: AccountsOptions) => {
  const shared = createShared(options)
  const { adapter, credentials, hasher, policy, spendDecoy } = shared
  const scopes = options.claims ?? STANDARD_CLAIMS
  const key = importSecretKey(options.secretKey)
  const hashingKey = importHashingKey(options.secretKey)
  const throttle = createThrottle(shared)
  const recovery = createRecovery(shared, hashingKey)
  const { creationOptions, verifyCreation, keep, ...passkeys } = createPasskeys({
    adapter,
    origin: options.origin,
    name: options.issuer,
    hashingKey,
    ttl: policy.passkeyTimeout
  })
  const { generationOf, issueResetToken, reset } = createReset(shared, throttle, recovery, { creationOptions, verifyCreation, keep })

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
      const accountId = shared.newAccountId(username)
      if (await shared.linkedElsewhere(accountId)) return { ok: false, reason: 'taken' } as const
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
      const { codes, hashes } = await recovery.issueRecoveryCodes(accountId)
      const now = new Date()
      const account = { accountId, ...signUp, recoveryCodes: hashes, failedAttempts: 0, createdAt: now, updatedAt: now }
      if ((await shared.linkedElsewhere(accountId)) || !(await credentials.create(account))) return { ok: false, reason: 'taken' }
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

  return {
    /** Pass as the adapter's `accounts`: `createProvider({ adapter: { ...adapter, accounts: accounts.store } })`. */
    store,

    /** The policy in force, defaults filled in, for screens that state it. */
    policy,

    async signUp(input: { username: string; password: string; claims?: Record<string, unknown> }): Promise<SignUpResult> {
      const username = normalizeUsername(input.username)
      const usernameProblem = oauthFieldError(username)
      if (usernameProblem) return { ok: false, reason: 'username', problem: usernameProblem }
      const problem = await shared.passwordProblem(input.password, username)
      if (problem) return { ok: false, reason: 'password', problem }
      const now = new Date()
      const accountId = shared.newAccountId(username)
      if (await shared.linkedElsewhere(accountId)) return { ok: false, reason: 'taken' }
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
      // FR-I7: past the maximum nothing can match, and it costs what an unknown username does, never a hash of its own length.
      if (password.length > DEFAULT_MAX_LENGTH) {
        await spendDecoy(password.slice(0, DEFAULT_MAX_LENGTH))
        return invalid
      }
      const normalized = normalizeUsername(username)
      const credential = await credentials.findByUsername(normalized)
      if (!credential?.passwordHash) return throttle.guessAtNobody(normalized, password, 'password', context)
      const { passwordHash } = credential
      const bucket = throttle.ownBucket(credential.accountId, 'password', context)
      const admitted = await throttle.admit(credential.accountId, lockedUntil(credential), bucket, password)
      if (admitted.refused) return admitted.refused
      if (!(await hasher.verify(password, passwordHash))) return throttle.fail(credential.accountId, bucket, admitted.slot, context)
      await throttle.succeed(bucket, admitted.slot)
      return { ok: true, accountId: credential.accountId, secondFactor: Boolean(credential.totp?.confirmedAt) }
    },

    /** A TOTP code or a recovery code, each accepted once (NFR-S5). Failures count towards the lockout. */
    async verifySecondFactor(accountId: string, code: string, context: SignInContext = {}): Promise<SecondFactorResult> {
      const credential = await credentials.find(accountId)
      if (!credential?.totp?.confirmedAt) return invalid
      const bucket = throttle.ownBucket(accountId, 'code', context)
      const admitted = await throttle.admit(accountId, lockedUntil(credential), bucket)
      if (admitted.refused) return admitted.refused

      const counter = await matchingCounter(await open(await key, accountId, credential.totp.secret), code.replace(/\s/g, ''))
      if (counter !== undefined && (await adapter.replay.claim('totp', `${accountId}:${counter}`, 3 * TOTP_PERIOD))) {
        await throttle.succeed(bucket, admitted.slot)
        return { ok: true, method: 'otp' }
      }

      if (await recovery.redeemRecoveryCode(credential, code)) {
        await throttle.succeed(bucket, admitted.slot)
        return { ok: true, method: 'recovery' }
      }

      return throttle.fail(accountId, bucket, admitted.slot, context)
    },

    /**
     * A recovery code in place of the lost passkey of an account with no password (FR-I8). It spends the code and answers a
     * reset token, for `reset.completeWithPasskey` or `reset.complete`; it signs no one in.
     */
    async recover(username: string, code: string, context: SignInContext = {}): Promise<RecoveryResult> {
      const normalized = normalizeUsername(username)
      const credential = await credentials.findByUsername(normalized)
      // G-9: every answer pays one hash, as a password's does, so how long it takes names no account.
      if (!credential || credential.passwordHash) return throttle.guessAtNobody(normalized, code, 'code', context)
      const { accountId } = credential
      const bucket = throttle.ownBucket(accountId, 'code', context)
      const admitted = await throttle.admit(accountId, lockedUntil(credential), bucket, code)
      if (admitted.refused) return admitted.refused
      const [redeemed] = await Promise.all([recovery.redeemRecoveryCode(credential, code), spendDecoy(code)])
      if (!redeemed) return throttle.fail(accountId, bucket, admitted.slot, context)
      await throttle.succeed(bucket, admitted.slot)
      return { ok: true, accountId, token: await issueResetToken(accountId) }
    },

    /** Replaces every recovery code; the old ones stop working at once. For an account with TOTP, or with no password. */
    async regenerateRecoveryCodes(accountId: string) {
      const credential = await credentials.find(accountId)
      if (!credential || (credential.passwordHash && !credential.totp?.confirmedAt)) return undefined
      const { codes, hashes } = await recovery.issueRecoveryCodes(accountId)
      await credentials.update(accountId, { recoveryCodes: hashes, updatedAt: new Date() })
      return { recoveryCodes: codes }
    },

    setPassword: passwordSetter(shared),

    /** WebAuthn: a sign-in of its own, by autofill, or a second factor beside TOTP; and an account's only credential (FR-I8). */
    passkeys: { ...passkeys, ...passkeySignUp },

    totp: createTotpEnrolment(shared, key, recovery),

    emailSignIn: createEmailSignIn(shared, generationOf),

    reset
  }
}

export type Accounts = ReturnType<typeof createAccounts>
