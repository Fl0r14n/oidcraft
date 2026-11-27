import type { Recovery } from './recovery'
import { open, seal } from './sealed'
import type { Shared } from './shared'
import { base32, matchingCounter, otpauthUri, TOTP_PERIOD } from './totp'

/** TOTP as a second factor after a password (FR-I7): begin, confirm with a first code, remove. */
export const createTotpEnrolment = ({ adapter, credentials, options }: Shared, key: Promise<CryptoKey>, recovery: Recovery) => ({
  /** Starts enrolment. The secret only takes effect once `confirm` sees a code generated from it. */
  async begin(accountId: string) {
    const credential = await credentials.find(accountId)
    if (!credential) return undefined
    if (credential.totp?.confirmedAt) return { ok: false, reason: 'enrolled' } as const
    // A second factor follows a password; an account without one signs in with a passkey, already two (FR-I8).
    if (!credential.passwordHash) return { ok: false, reason: 'passwordless' } as const
    const secret = crypto.getRandomValues(new Uint8Array(20))
    await credentials.update(accountId, { totp: { secret: await seal(await key, accountId, secret) }, updatedAt: new Date() })
    const encoded = base32(secret)
    return { ok: true, secret: encoded, uri: otpauthUri(encoded, options.issuer, credential.username) } as const
  },

  /** The first code proves the app holds the secret. Returns the recovery codes, shown once and stored hashed. */
  async confirm(accountId: string, code: string) {
    const credential = await credentials.find(accountId)
    if (!credential?.totp || credential.totp.confirmedAt) return undefined
    const counter = await matchingCounter(await open(await key, accountId, credential.totp.secret), code.replace(/\s/g, ''))
    if (counter === undefined || !(await adapter.replay.claim('totp', `${accountId}:${counter}`, 3 * TOTP_PERIOD))) return undefined
    const { codes, hashes } = await recovery.issueRecoveryCodes(accountId)
    await credentials.update(accountId, {
      totp: { secret: credential.totp.secret, confirmedAt: new Date() },
      recoveryCodes: hashes,
      updatedAt: new Date()
    })
    return { recoveryCodes: codes }
  },

  async remove(accountId: string) {
    await credentials.update(accountId, { totp: undefined, recoveryCodes: undefined, updatedAt: new Date() })
  },

  async status(accountId: string) {
    const credential = await credentials.find(accountId)
    return {
      enrolled: Boolean(credential?.totp?.confirmedAt),
      recoveryCodesLeft: credential?.recoveryCodes?.length ?? 0
    }
  }
})
