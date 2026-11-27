/// <reference types="bun" />
import type { AccountStore, Adapter, CredentialsAdapter } from '@oidcraft/provider'
import { type Accounts, createAccounts, type EmailSignInIssue, generateSecretKey } from '@oidcraft/provider/accounts'
import { bunPasswordHasher } from '@oidcraft/provider/runtimes/bun'
import { devSecret } from './dev-secrets'
import { optional, required } from './env'

const PROFILE = ['name', 'given_name', 'family_name', 'preferred_username', 'picture', 'locale']

const secretKey = async () => {
  const key = optional('OIDCRAFT_TOTP_KEY')
  if (key) return key
  if (Bun.env.NODE_ENV === 'production') throw new Error('OIDCRAFT_TOTP_KEY is required in production')
  console.warn('[oidcraft] no OIDCRAFT_TOTP_KEY: using a development key kept beside the data')
  return devSecret('totp-key.json', generateSecretKey)
}

const totpKey = await secretKey()

export const createDemoAccounts = (adapter: CredentialsAdapter, issuerName: string, issuerUrl: string) =>
  createAccounts({
    adapter,
    hasher: bunPasswordHasher,
    secretKey: totpKey,
    issuer: issuerName,
    origin: issuerUrl
  })

/** Local accounts first; a brokered account has no password and reports the mapped claims linking recorded (FR-F7). */
export const accountStore = (adapter: Adapter, accounts: Accounts): AccountStore => ({
  async find(accountId) {
    const local = await accounts.store.find(accountId)
    if (local) return local
    const [linked] = (await adapter.identities?.listForAccount(accountId)) ?? []
    return linked ? { accountId, claims: linked.claims } : undefined
  },
  async claims(accountId, scopes, claims) {
    const local = await accounts.store.claims(accountId, scopes, claims)
    if (local) return local
    const [linked] = (await adapter.identities?.listForAccount(accountId)) ?? []
    if (!linked) return undefined
    return Object.fromEntries(
      Object.entries(linked.claims).filter(
        ([name]) =>
          claims.includes(name) ||
          (scopes.includes('profile') && PROFILE.includes(name)) ||
          (scopes.includes('email') && ['email', 'email_verified'].includes(name))
      )
    )
  }
})

/**
 * Demo accounts only when OIDCRAFT_DEMO_ACCOUNTS=on, with the password OIDCRAFT_DEMO_PASSWORD names and no default: a
 * deployment started from this code must not open with accounts whose password is in the repository. The conformance
 * suite's user exists only when the suite is configured.
 */
export const seedDemoAccounts = async (accounts: Accounts, adapter: Adapter) => {
  // Looked up first: signing up hashes the password, and argon2id is deliberately not cheap.
  const signUp = async (person: Parameters<Accounts['signUp']>[0]) => {
    if (!(await adapter.credentials?.findByUsername(person.username))) await accounts.signUp(person)
  }
  if (optional('OIDCRAFT_DEMO_ACCOUNTS') === 'on') await seedPeople(signUp)
  if (optional('OIDCRAFT_CONFORMANCE_SUITE')) await seedConformanceUser(signUp)
}

type SignUp = (person: Parameters<Accounts['signUp']>[0]) => Promise<void>

const seedPeople = async (signUp: SignUp) => {
  const password = required('OIDCRAFT_DEMO_PASSWORD')
  const people = [
    { username: 'admin', claims: { name: 'Administrator', email: 'admin@example.invalid', email_verified: true } },
    {
      username: 'ada',
      claims: { name: 'Ada Lovelace', given_name: 'Ada', family_name: 'Lovelace', email: 'ada@example.invalid', email_verified: true }
    },
    {
      username: 'grace',
      claims: { name: 'Grace Hopper', given_name: 'Grace', family_name: 'Hopper', email: 'grace@example.invalid', email_verified: false }
    }
  ]
  for (const person of people) await signUp({ ...person, password })
  console.log(`[oidcraft] demo accounts: ${people.map(person => person.username).join(', ')} — password from OIDCRAFT_DEMO_PASSWORD`)
}

const seedConformanceUser = (signUp: SignUp) =>
  signUp({
    username: 'conformance-user',
    password: 'conformance-password',
    // oidcc-scope-profile warns unless every profile claim (OIDC Core §5.4) comes back.
    claims: {
      name: 'Conformance User',
      given_name: 'Conformance',
      middle_name: 'Q',
      family_name: 'User',
      nickname: 'conformance',
      preferred_username: 'conformance-user',
      profile: 'https://example.invalid/conformance-user',
      picture: 'https://example.invalid/conformance-user.png',
      website: 'https://example.invalid',
      gender: 'unspecified',
      birthdate: '0000-01-01',
      zoneinfo: 'Europe/London',
      locale: 'en',
      updated_at: 1767225600,
      email: 'conformance@example.invalid',
      email_verified: true
    }
  })

/** The demo's mail for an email sign-in (FR-I9): a link, a pointer to the way this account signs in, or nothing at all. */
export const sendEmailSignIn = (issued: EmailSignInIssue, issuer: string) => {
  if (issued.ok) {
    console.log(`[demo mail] to ${issued.address}: sign in at ${new URL(`/email-sign-in?token=${issued.token}`, issuer)}`)
  } else if (issued.reason === 'passkey' || issued.reason === 'unverified') {
    const way = issued.reason === 'passkey' ? 'its passkey' : 'its password'
    console.log(`[demo mail] to ${issued.address}: this account does not sign in by email; use ${way} on the sign-in screen`)
  }
}

/** The demo's mail: a deployment emails this link and never shows it, or the form hands accounts to anyone. */
export const sendRecoveryLink = (accountId: string, token: string, issuer: string) =>
  console.log(`[demo mail] to ${accountId}: get back into your account at ${new URL(`/reset?token=${token}`, issuer)}`)
