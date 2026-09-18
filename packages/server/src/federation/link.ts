import type { Adapter, FederatedIdentity } from 'oidcraft'
import type { BrokeredIdentity, LinkPolicy } from './types'

export type LinkResult = { accountId: string; created: boolean } | { needsInteraction: 'link'; candidate: string }

export type LinkOptions = {
  policy?: LinkPolicy
  /** Finds an existing local account by verified email. Required by the `verified-email` policy. */
  findByEmail?: (email: string) => Promise<string | undefined>
  /** Creates a local account. Without it an unknown identity is refused rather than silently made. */
  createAccount?: (identity: BrokeredIdentity) => Promise<string>
}

/**
 * Attaches a brokered identity to a local account (FR-F5).
 *
 * `subject` — the default — matches on `(provider, subject)` and nothing else. Matching on an email
 * address instead is account takeover the moment an upstream does not verify addresses or lets a
 * user change one, so `verified-email` additionally demands `email_verified` from the upstream, and
 * `interactive` refuses to decide and hands the question back (NFR-S8).
 */
export const linkIdentity = async (adapter: Adapter, identity: BrokeredIdentity, options: LinkOptions = {}): Promise<LinkResult> => {
  if (!adapter.identities) throw new Error('this adapter has no FederatedIdentityStore; brokering needs one (FR-F5)')

  const existing = await adapter.identities.find(identity.provider, identity.subject)
  if (existing) return { accountId: existing.accountId, created: false }

  const policy: LinkPolicy = options.policy ?? 'subject'

  if (policy !== 'subject' && identity.email) {
    // An unverified address proves nothing: the upstream may never have checked it.
    const verified = identity.claims.email_verified === true
    if (verified && options.findByEmail) {
      const candidate = await options.findByEmail(identity.email)
      if (candidate) {
        if (policy === 'interactive') return { needsInteraction: 'link', candidate }
        await link(adapter, identity, candidate)
        return { accountId: candidate, created: false }
      }
    }
  }

  if (!options.createAccount) {
    throw new Error(`no local account matches ${identity.provider}:${identity.subject} and no createAccount was supplied`)
  }

  const accountId = await options.createAccount(identity)
  await link(adapter, identity, accountId)
  return { accountId, created: true }
}

const link = async (adapter: Adapter, identity: BrokeredIdentity, accountId: string) => {
  const record: FederatedIdentity = {
    accountId,
    provider: identity.provider,
    subject: identity.subject,
    ...(identity.email && { email: identity.email }),
    claims: identity.claims,
    linkedAt: new Date()
  }
  await adapter.identities?.link(record)
}
