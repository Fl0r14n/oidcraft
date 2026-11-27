import { randomString } from '@oidcraft/core'
import type { Credential } from '@oidcraft/provider'
import { digest, invalid, locked, lockedUntil, normalizeUsername, type Shared, usernameProblem } from './shared'

export type AddressProblem = 'required' | 'tooLong' | 'invalid'

/** FR-I9: every refusal but `address` is answered as a success is; `passkey` and `unverified` say what to send instead. */
export type EmailSignInIssue =
  | { ok: true; token: string; address: string; accountId: string | undefined }
  | { ok: false; reason: 'address'; problem: AddressProblem }
  | { ok: false; reason: 'passkey' | 'unverified' | 'unknown'; address: string }
  | { ok: false; reason: 'locked'; until: Date }

/** `interactionId` is the one to finish with `provider.interactions.completeHere`, after the TOTP step when `secondFactor`. */
export type EmailSignInResult =
  | { ok: true; accountId: string; interactionId: string; secondFactor: boolean; signedUp: boolean }
  | { ok: false; reason: 'invalid' | 'passkey' }
  | { ok: false; reason: 'locked'; until: Date }

/** What an email sign-in token is issued for: `provider.interactions.find`'s answer is one. */
export type EmailSignInInteraction = { id: string; clientId: string; expiresAt: Date }

type EmailSignInPayload = {
  address: string
  interactionId: string
  generation?: string
  signUp?: { claims: Record<string, unknown> }
}

// The address becomes the username, so it is one first (RFC 8265), then an address.
const addressProblem = (address: string): AddressProblem | undefined =>
  usernameProblem(address) ?? (/^[^@]+@[^@]+$/.test(address) ? undefined : 'invalid')

/** Sign-in, and sign-up where the host offers it, by a single-use link to an address (FR-I9). */
export const createEmailSignIn = (shared: Shared, generationOf: (accountId: string) => Promise<string>) => {
  const { adapter, credentials, policy } = shared

  /** Counted per address whether or not an account has it, so the count names no account either (NFR-S12). */
  const admitEmailSignIn = async (address: string) => {
    for (let slot = 0; slot < policy.emailSignInsPerAddress; slot++) {
      if (await adapter.replay.claim('email_sign_in', `${address}:${slot}`, policy.emailSignInWindow)) return true
    }
    return false
  }

  /** FR-I9: a password beside an address never proven on it may be whoever signed up with someone else's address. */
  const checkEmailSignIn = async (credential: Credential, address: string) => {
    if ((await adapter.passkeys.listForAccount(credential.accountId)).length) return { ok: false, reason: 'passkey' } as const
    const { email, email_verified } = credential.claims
    const proven = email_verified === true && typeof email === 'string' && normalizeUsername(email) === address
    return credential.passwordHash && !proven ? ({ ok: false, reason: 'unverified' } as const) : ({ ok: true } as const)
  }

  const liveEmailSignIn = async (id: string) => {
    const artifact = await adapter.artifacts.find('email_sign_in', id)
    if (!artifact || artifact.consumedAt) return undefined
    const { generation } = artifact.payload as EmailSignInPayload
    return !artifact.accountId || generation === (await generationOf(artifact.accountId)) ? artifact : undefined
  }

  return {
    /** A single-use token for the host to send (FR-A1); an address with no account gets one only with `signUp` (FR-I9). */
    async issue(
      address: string,
      interaction: EmailSignInInteraction,
      options: { signUp?: { claims?: Record<string, unknown> } } = {}
    ): Promise<EmailSignInIssue> {
      const normalized = normalizeUsername(address)
      const problem = addressProblem(normalized)
      if (problem) return { ok: false, reason: 'address', problem }
      if (!(await admitEmailSignIn(normalized))) {
        return { ok: false, reason: 'locked', until: new Date(Date.now() + policy.emailSignInWindow * 1000) }
      }
      const credential = await credentials.findByUsername(normalized)
      if (!credential && !options.signUp) return { ok: false, reason: 'unknown', address: normalized }
      const checked = credential ? await checkEmailSignIn(credential, normalized) : undefined
      if (checked && !checked.ok) return { ok: false, reason: checked.reason, address: normalized }
      const token = randomString(43)
      const payload: EmailSignInPayload = {
        address: normalized,
        interactionId: interaction.id,
        ...(credential ? { generation: await generationOf(credential.accountId) } : { signUp: { claims: options.signUp?.claims ?? {} } })
      }
      await adapter.artifacts.upsert({
        id: await digest(token),
        kind: 'email_sign_in',
        clientId: interaction.clientId,
        ...(credential && { accountId: credential.accountId }),
        payload,
        expiresAt: new Date(Math.min(Date.now() + policy.emailSignInTtl * 1000, interaction.expiresAt.getTime()))
      })
      return { ok: true, token, address: normalized, accountId: credential?.accountId }
    },

    /** A live token's address and interaction, spending nothing: mail scanners open links too (FR-I9). */
    async find(token: string) {
      const artifact = await liveEmailSignIn(await digest(token))
      if (!artifact) return undefined
      const { address, interactionId } = artifact.payload as EmailSignInPayload
      return { address, interactionId }
    },

    async redeem(token: string): Promise<EmailSignInResult> {
      const id = await digest(token)
      const artifact = await liveEmailSignIn(id)
      if (!artifact || !(await adapter.artifacts.consume('email_sign_in', id))) return invalid
      const { address, interactionId, signUp } = artifact.payload as EmailSignInPayload
      let credential = artifact.accountId ? await credentials.find(artifact.accountId) : undefined
      let signedUp = false
      if (!artifact.accountId && signUp) {
        const now = new Date()
        const accountId = shared.newAccountId(address)
        if (await shared.linkedElsewhere(accountId)) return invalid
        const account: Credential = {
          accountId,
          username: address,
          claims: { ...signUp.claims, email: address, email_verified: true },
          failedAttempts: 0,
          createdAt: now,
          updatedAt: now
        }
        signedUp = await credentials.create(account)
        credential = signedUp ? account : await credentials.findByUsername(address)
      }
      if (credential?.username !== address) return invalid
      const checked = signedUp ? undefined : await checkEmailSignIn(credential, address)
      if (checked && !checked.ok) return checked.reason === 'passkey' ? { ok: false, reason: 'passkey' } : invalid
      const until = lockedUntil(credential)
      if (until) return locked(until)
      return { ok: true, accountId: credential.accountId, interactionId, secondFactor: Boolean(credential.totp?.confirmedAt), signedUp }
    }
  }
}
