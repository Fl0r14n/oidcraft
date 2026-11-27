import { randomString } from '@oidcraft/core'
import { type createPasskeys, displayNameOf, nameProblem, type PasskeyNameProblem, type RegistrationResponseJSON } from './passkeys'
import { RECOVERY_TOMBSTONE, type Recovery } from './recovery'
import { digest, invalid, normalizeUsername, passwordSetter, type Shared, type SignInContext } from './shared'
import type { Throttle } from './throttle'

export type PasskeyResetResult =
  | { ok: true; accountId: string; recoveryCodes: string[] }
  | { ok: false; reason: 'invalid' | 'taken' }
  | { ok: false; reason: 'name'; problem: PasskeyNameProblem }

/** Never a token's digest, which has no colon, so it shares the reset tokens' kind without being one. */
const generationId = (accountId: string) => `generation:${accountId}`

const resetBinding = (tokenDigest: string) => `reset:${tokenDigest}`

/** Single-use reset tokens the host delivers (FR-A1), finished with a password or a passkey (FR-I7, FR-I8). */
export const createReset = (
  shared: Shared,
  throttle: Throttle,
  recovery: Recovery,
  passkeys: Pick<ReturnType<typeof createPasskeys>, 'creationOptions' | 'verifyCreation' | 'keep'>
) => {
  const { adapter, credentials, policy } = shared
  const setPassword = passwordSetter(shared)

  /** FR-I7: what a completed reset moves on, so every token issued before it is spent with it. */
  const generationOf = async (accountId: string) =>
    ((await adapter.artifacts.find('password_reset', generationId(accountId)))?.payload as { generation?: string } | undefined)
      ?.generation ?? '0'

  const issueResetToken = async (accountId: string) => {
    const token = randomString(43)
    await adapter.artifacts.upsert({
      id: await digest(token),
      kind: 'password_reset',
      clientId: '',
      accountId,
      payload: { generation: await generationOf(accountId) },
      expiresAt: Date.now() + policy.resetTtl * 1000
    })
    return token
  }

  /** FR-I7: a completed reset spends every other reset and email sign-in token of the account, issued under an older generation. */
  const liveReset = async (id: string) => {
    const artifact = await adapter.artifacts.find('password_reset', id)
    if (!artifact?.accountId || artifact.consumedAt) return undefined
    const { generation } = artifact.payload as { generation?: string }
    return generation === (await generationOf(artifact.accountId)) ? { ...artifact, accountId: artifact.accountId } : undefined
  }

  /** What a reset finishes with, whichever credential it set: the old ones' sessions end and their tokens are revoked (FR-T7). */
  const afterReset = async (accountId: string, context: SignInContext) => {
    await adapter.artifacts.upsert({
      id: generationId(accountId),
      kind: 'password_reset',
      clientId: '',
      accountId,
      payload: { generation: randomString(8) },
      expiresAt: Date.now() + RECOVERY_TOMBSTONE * 1000
    })
    await throttle.lift(accountId, context)
    for (const session of await adapter.sessions.listForAccount(accountId)) await adapter.sessions.destroy(session.id)
    // FR-T7: an offline refresh token carries its own sign-in and would outlive the sessions. The consent stays, under a
    // new id, so a token a racing refresh writes after the sweep names a grant that is gone (FR-T3).
    for (const grant of await adapter.grants.listForAccount(accountId)) {
      await adapter.grants.destroy(grant.id)
      await adapter.artifacts.destroyByGrantId(grant.id)
      await adapter.grants.merge({ ...grant, id: randomString() })
    }
  }

  const reset = {
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
      const artifact = await liveReset(id)
      const credential = artifact && (await credentials.find(artifact.accountId))
      if (!credential) return undefined
      const { accountId, username, claims } = credential
      return passkeys.creationOptions(
        { accountId, username, displayName: displayNameOf(username, claims) },
        { ceremony: 'create', binding: resetBinding(id) }
      )
    },

    /**
     * Adds the passkey made from `passkeyOptions` in place of the password and TOTP, with new recovery codes to show once, and, as
     * `complete` does, ends what the old credentials opened: after a compromise, the password left beside it is the intruder's (FR-I7).
     */
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
      const created = await passkeys.verifyCreation(response, { ceremony: 'create', binding: resetBinding(id) })
      if (!created) return invalid
      const { accountId } = created
      const artifact = await liveReset(id)
      if (artifact?.accountId !== accountId || !(await adapter.artifacts.consume('password_reset', id))) return invalid
      const kept = await passkeys.keep(created.passkey(passkeyName))
      if (!kept.ok) return { ok: false, reason: 'taken' }
      const { codes, hashes } = await recovery.issueRecoveryCodes(accountId)
      await credentials.update(accountId, { passwordHash: undefined, totp: undefined, recoveryCodes: hashes, updatedAt: Date.now() })
      await afterReset(accountId, context)
      return { ok: true, accountId, recoveryCodes: codes }
    },

    /** Sets the new password, ends every session the old one opened and revokes the tokens issued to the account (FR-T7). */
    async complete(token: string, password: string, context: SignInContext = {}) {
      const id = await digest(token)
      const artifact = await liveReset(id)
      const problem = await shared.passwordProblem(password, artifact ? ((await credentials.find(artifact.accountId))?.username ?? '') : '')
      if (problem) return { ok: false, reason: 'password', problem } as const
      if (!artifact || !(await adapter.artifacts.consume('password_reset', id))) return { ok: false, reason: 'invalid' } as const
      const set = await setPassword(artifact.accountId, password)
      if (!set.ok) return { ok: false, reason: 'invalid' } as const
      await afterReset(artifact.accountId, context)
      return { ok: true, accountId: artifact.accountId } as const
    }
  }

  return { generationOf, issueResetToken, reset }
}
