import type { BrokeringAdapter, CredentialsAdapter, LinkedIdentity } from '@oidcraft/provider'
import type { BrokeredIdentity, LinkPolicy } from './types'

export type LinkResult = { accountId: string; created: boolean } | { needsInteraction: 'link'; candidate: string }

export type LinkOptions = {
  policy?: LinkPolicy
  /** Finds an existing local account by verified email. Required by the `verified-email` policy. */
  findByEmail?: (email: string) => Promise<string | undefined>
  /** Creates a local account. Without it an unknown identity is refused rather than silently made. */
  createAccount?: (identity: BrokeredIdentity) => Promise<string>
}

// Strictest first: proving the existing account beats trusting an upstream's word that it checked the address (NFR-S8).
const STRICTNESS: LinkPolicy[] = ['subject', 'interactive', 'verified-email']

/** The upstream's policy and the call's: whichever is stricter, so neither can loosen the other; `subject` when neither says. */
const strictest = (policies: (LinkPolicy | undefined)[]) => STRICTNESS.find(policy => policies.includes(policy)) ?? 'subject'

/**
 * Attaches a brokered identity to a local account (FR-F5). `subject`, the default, matches `(upstream, subject)` only;
 * `verified-email` demands `email_verified`, as an unverified address is account takeover (NFR-S8).
 */
export const linkIdentity = async (
  adapter: BrokeringAdapter,
  identity: BrokeredIdentity,
  options: LinkOptions = {}
): Promise<LinkResult> => {
  const existing = await adapter.identities.find(identity.upstream, identity.subject)
  if (existing) return { accountId: existing.accountId, created: false }

  const policy = strictest([options.policy, identity.linkPolicy])

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
    throw new Error(`no local account matches ${identity.upstream}:${identity.subject} and no createAccount was supplied`)
  }

  const accountId = await options.createAccount(identity)
  // FR-F5: one id names one account. A created one a local credential holds would hand that account to the upstream's user.
  const local = adapter as Partial<CredentialsAdapter>
  if ((await local.credentials?.find(accountId)) || (await local.passkeys?.listForAccount(accountId))?.length) {
    throw new Error(`createAccount returned ${accountId}, which a local account already holds; a created account needs an id of its own`)
  }
  await link(adapter, identity, accountId)
  return { accountId, created: true }
}

const link = async (adapter: BrokeringAdapter, identity: BrokeredIdentity, accountId: string) => {
  const record: LinkedIdentity = {
    accountId,
    upstream: identity.upstream,
    subject: identity.subject,
    ...(identity.email && { email: identity.email }),
    claims: identity.claims,
    createdAt: new Date()
  }
  await adapter.identities.upsert(record)
}
