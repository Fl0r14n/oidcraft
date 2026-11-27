import type { Credential, Seconds } from '@oidcraft/provider'
import { base64url } from 'jose'
import type { Shared } from './shared'
import { base32 } from './totp'

/** Ten base32 characters in two groups: about 50 bits, enough for a code that is also rate-limited. */
const recoveryCode = () => {
  const text = base32(crypto.getRandomValues(new Uint8Array(7)))
    .slice(0, 10)
    .toLowerCase()
  return `${text.slice(0, 5)}-${text.slice(5)}`
}

const normalizeRecoveryCode = (code: string) => code.trim().toLowerCase().replace(/[\s-]/g, '')

/** Long enough that a used recovery code cannot come back while it could still be on someone's paper. */
export const RECOVERY_TOMBSTONE: Seconds = 10 * 365 * 24 * 3600

/** Recovery codes, stored keyed and bound to their account, each usable once (FR-I7, FR-I8). */
export const createRecovery = ({ adapter, credentials, policy }: Shared, hashingKey: Promise<CryptoKey>) => {
  /** Keyed and bound to the account: 50 bits unsalted are a dictionary away from a dump (FR-I7). */
  const recoveryHash = async (accountId: string, code: string) =>
    base64url.encode(
      new Uint8Array(
        await crypto.subtle.sign('HMAC', await hashingKey, new TextEncoder().encode(`${accountId}:${normalizeRecoveryCode(code)}`))
      )
    )

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
    // Read again after the claim, and only the codes written: a reset or TOTP change in between must not be undone.
    const current = await credentials.find(accountId)
    if (current) {
      await credentials.update(accountId, {
        recoveryCodes: (current.recoveryCodes ?? []).filter(stored => stored !== hash),
        updatedAt: Date.now()
      })
    }
    return true
  }

  return { issueRecoveryCodes, redeemRecoveryCode }
}

export type Recovery = ReturnType<typeof createRecovery>
