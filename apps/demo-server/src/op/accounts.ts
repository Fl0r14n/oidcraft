/// <reference types="bun" />
import type { AccountStore, Adapter } from 'oidcraft'
import { type Accounts, createAccounts, generateSecretKey } from 'oidcraft/accounts'
import { bunPasswordHasher } from 'oidcraft/runtimes/bun'
import { optional, withDefault } from './env'

const PROFILE = ['name', 'given_name', 'family_name', 'preferred_username', 'picture', 'locale']

/**
 * Production supplies OIDCRAFT_TOTP_KEY. Without it development generates one per process, and every
 * enrolled authenticator stops working at the next restart — say so rather than fail later.
 */
let generatedTotpKey: string | undefined

const totpKey = () => {
  if (generatedTotpKey) return generatedTotpKey
  const key = optional('OIDCRAFT_TOTP_KEY')
  if (key) return key
  if (Bun.env.NODE_ENV === 'production') throw new Error('OIDCRAFT_TOTP_KEY is required in production')
  console.warn('[oidcraft] no OIDCRAFT_TOTP_KEY: authenticator enrolments last until this process exits')
  generatedTotpKey = generateSecretKey()
  return generatedTotpKey
}

export const createDemoAccounts = (adapter: Adapter, issuerName: string) =>
  createAccounts({
    adapter,
    hasher: bunPasswordHasher,
    secretKey: totpKey(),
    issuer: issuerName,
    // The demo's subjects are its usernames, so OIDCRAFT_ADMINS can name people rather than random ids.
    newAccountId: username => username
  })

/**
 * Local accounts first; an account created by brokering has no password and reports what its
 * upstream said instead, the mapped claims linking recorded (FR-F7).
 */
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
          (scopes.includes('profile') && PROFILE.includes(name)) || (scopes.includes('email') && ['email', 'email_verified'].includes(name))
      )
    )
  }
})

/**
 * Demo only: three people to sign in as, with one password from OIDCRAFT_DEMO_PASSWORD. The
 * conformance suite's user exists only when the suite is configured, with the password its plan types.
 */
export const seedDemoAccounts = async (accounts: Accounts, adapter: Adapter) => {
  // Looked up first: registering hashes the password, and argon2id is deliberately not cheap.
  const register = async (person: Parameters<Accounts['register']>[0]) => {
    if (!(await adapter.credentials?.findByUsername(person.username))) await accounts.register(person)
  }
  const password = withDefault('OIDCRAFT_DEMO_PASSWORD', 'correct horse battery staple')
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
  for (const person of people) await register({ ...person, password })
  if (optional('OIDCRAFT_CONFORMANCE_SUITE')) {
    await register({
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
  }
  console.log(`[oidcraft] demo accounts: ${people.map(person => person.username).join(', ')} — password from OIDCRAFT_DEMO_PASSWORD`)
}
