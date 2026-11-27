import { randomString } from '@oidcraft/core'
import { addressBucket, type Expiring, type Seconds } from '@oidcraft/provider'
import { digest, invalid, liveLock, locked, type Shared, type SignInContext } from './shared'

type Attempts = { generation: string; lock?: Expiring }

type Bucket = { scope: string; limit: number; ttl: Seconds; accountId: string | undefined }

const SLOTS = 'sign_in'

/** Failed passwords and codes, counted per account and address and per account alone (FR-I7, G-9). */
export const createThrottle = ({ adapter, policy, spendDecoy }: Shared) => {
  const attemptsAt = async (scope: string) => (await adapter.artifacts.find('sign_in_attempts', scope))?.payload as Attempts | undefined
  const lockedAt = async (scope: string) => {
    const attempts = (await attemptsAt(scope)) as (Attempts & { lockedUntil?: number }) | undefined
    // NFR-D6: one written as `lockedUntil` before `lock` is still a lock; a deploy must not lift it.
    return liveLock(attempts?.lock ?? (attempts?.lockedUntil ? { expiresAt: attempts.lockedUntil } : undefined))
  }

  /** Every address together, never reset by a good sign-in: otherwise the owner signing in would restart a spread-out guess (G-9). */
  const accountWide = (accountId: string, owned = true): Bucket => ({
    scope: `${accountId}:*`,
    limit: policy.maxFailedAttemptsPerAccount,
    ttl: policy.failureWindow,
    accountId: owned ? accountId : undefined
  })
  /** This address, or the account when there is none (G-9); a second factor's apart, so a known password does not reset it. */
  const ownBucket = (accountId: string, factor: 'password' | 'code', context: SignInContext, owned = true): Bucket => ({
    scope: `${accountId}:${factor === 'code' ? 'code:' : ''}${context.clientIp ? addressBucket(context.clientIp) : '-'}`,
    limit: policy.maxFailedAttempts,
    ttl: policy.lockout,
    accountId: owned ? accountId : undefined
  })

  /** A username no password signs in to, counted as an account's is, so locking out names no account either (G-9). */
  const nobody = async (username: string) => `?${await digest(username)}`

  const lockFor = async (accountId: string, hostLock: Expiring | undefined, bucket: Bucket) =>
    hostLock ?? (await lockedAt(accountWide(accountId).scope)) ?? (await lockedAt(bucket.scope))

  /** Kept as long as a slot of the generation can live; a new one frees every slot, so the account-wide lock keeps its own (G-9). */
  const renew = async (bucket: Bucket, lock?: Expiring, generation = randomString(8)) =>
    adapter.artifacts.upsert({
      id: bucket.scope,
      kind: 'sign_in_attempts',
      clientId: '',
      ...(bucket.accountId && { accountId: bucket.accountId }),
      payload: { generation, ...(lock && { lock }) } satisfies Attempts,
      expiresAt: (lock?.expiresAt ?? Date.now()) + bucket.ttl * 1000
    })

  /** Atomic: a read-then-write count lets parallel guesses all pass a check none of them has yet failed (G-9). */
  const claimSlot = async (bucket: Bucket) => {
    const generation = (await attemptsAt(bucket.scope))?.generation ?? '0'
    for (let slot = 0; slot < bucket.limit; slot++) {
      if (await adapter.replay.claim(SLOTS, `${bucket.scope}:${generation}:${slot}`, bucket.ttl)) return slot
    }
    return undefined
  }

  const lockoutFromNow = () => ({ expiresAt: Date.now() + policy.lockout * 1000 })

  /** Before the slow verify, so at most `limit` guesses run at once; a locked account still pays one hash, or names leak (FR-I7). */
  const admit = async (accountId: string, hostLock: Expiring | undefined, bucket: Bucket, password?: string) => {
    const lockedFor = await lockFor(accountId, hostLock, bucket)
    const slot = lockedFor ? undefined : await claimSlot(bucket)
    if (slot === undefined) {
      if (password !== undefined) await spendDecoy(password)
      return { refused: locked(lockedFor ?? lockoutFromNow()) }
    }
    return { slot }
  }

  const fail = async (accountId: string, bucket: Bucket, slot: number, context: SignInContext) => {
    const lock = lockoutFromNow()
    if (context.clientIp) {
      const wide = accountWide(accountId, bucket.accountId !== undefined)
      const counted = await claimSlot(wide)
      if (counted === undefined || counted === wide.limit - 1) {
        await renew(wide, lock, (await attemptsAt(wide.scope))?.generation ?? '0')
        return locked(lock)
      }
    }
    if (slot < bucket.limit - 1) return invalid
    await renew(bucket, lock)
    return locked(lock)
  }

  /** Only a bucket someone failed in this generation is renewed, so a clean sign-in writes nothing. */
  const succeed = async (bucket: Bucket, slot: number) => {
    if (slot > 0) await renew(bucket)
  }

  /** Every way in to an account nothing signs in to by this secret pays what one that does would, lockout included (G-9). */
  const guessAtNobody = async (username: string, secret: string, factor: 'password' | 'code', context: SignInContext) => {
    const id = await nobody(username)
    const bucket = ownBucket(id, factor, context, false)
    const admitted = await admit(id, undefined, bucket, secret)
    if (admitted.refused) return admitted.refused
    await spendDecoy(secret)
    return fail(id, bucket, admitted.slot, context)
  }

  /** G-9: guesses at a credential that is gone lock nothing; a fresh generation, so no slot of the old one counts. */
  const lift = async (accountId: string, context: SignInContext) => {
    const buckets = [accountWide(accountId), ownBucket(accountId, 'password', {}), ownBucket(accountId, 'code', {})]
    if (context.clientIp) buckets.push(ownBucket(accountId, 'password', context), ownBucket(accountId, 'code', context))
    for (const bucket of buckets) await renew(bucket)
  }

  return { ownBucket, admit, fail, succeed, guessAtNobody, lift }
}

export type Throttle = ReturnType<typeof createThrottle>
