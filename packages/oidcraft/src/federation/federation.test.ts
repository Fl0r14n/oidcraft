import { describe, expect, test } from 'bun:test'
import { memoryAdapter } from '../adapters/memory'
import type { Adapter } from '../index'
import { localSubject, pickClaims, renameClaims } from './claims'
import { linkIdentity } from './link'
import { selectUpstream } from './select'
import type { BrokeredIdentity, UpstreamProvider } from './types'

const provider = (over: Partial<UpstreamProvider> = {}): UpstreamProvider => ({
  id: 'entra',
  issuer: 'https://login.microsoftonline.com/common/v2.0',
  clientId: 'c',
  scopes: ['openid', 'email'],
  ...over
})

const identity = (over: Partial<BrokeredIdentity> = {}): BrokeredIdentity => ({
  provider: 'entra',
  subject: 'up-1',
  claims: {},
  ...over
})

describe('home-realm discovery', () => {
  const providers = [provider({ id: 'entra', domains: ['corp.example'] }), provider({ id: 'google', domains: ['gmail.com'] })]

  test('an explicit id wins', () => {
    expect(selectUpstream(providers, {}, 'google').chosen?.id).toBe('google')
  })

  test('an explicit id outside the allowed list is refused', () => {
    expect(selectUpstream(providers, { allowed: ['entra'] }, 'google').chosen).toBeUndefined()
  })

  test('the email domain selects the provider that owns it', () => {
    expect(selectUpstream(providers, { loginHint: 'ada@corp.example' }).chosen?.id).toBe('entra')
  })

  test('acr_values can name a provider', () => {
    expect(selectUpstream(providers, { acrValues: ['urn:oidcraft:idp:google'] }).chosen?.id).toBe('google')
  })

  test('a single allowed provider is chosen without a hint', () => {
    expect(selectUpstream(providers, { allowed: ['google'] }).chosen?.id).toBe('google')
  })

  // FR-F4: it asks rather than guessing.
  test('an ambiguous request returns the candidates and chooses nothing', () => {
    const { chosen, candidates } = selectUpstream(providers, {})
    expect(chosen).toBeUndefined()
    expect(candidates).toHaveLength(2)
  })

  test('an unknown domain does not fall through to an arbitrary provider', () => {
    expect(selectUpstream(providers, { loginHint: 'ada@elsewhere.test' }).chosen).toBeUndefined()
  })
})

describe('claim mapping', () => {
  const upstream = { sub: 'up-1', iss: 'https://up', name: 'Ada', email: 'ada@corp.example', email_verified: true, secret: 'x' }

  // FR-F7: nothing crosses without the mapper saying so.
  test('only allowed claims cross', () => {
    const mapped = pickClaims()(upstream)
    expect(mapped.name).toBe('Ada')
    expect(mapped).not.toHaveProperty('secret')
  })

  // The subject is meaningful only within its upstream, so it never becomes a local one.
  test('sub and the protocol claims are never mapped', () => {
    const mapped = pickClaims(['sub', 'iss', 'name'])(upstream)
    expect(mapped).not.toHaveProperty('sub')
    expect(mapped).not.toHaveProperty('iss')
    expect(mapped.name).toBe('Ada')
  })

  test('renaming cannot smuggle a value into sub', () => {
    expect(renameClaims({ name: 'sub' })(upstream)).not.toHaveProperty('sub')
  })

  test('renaming maps what it is told to', () => {
    expect(renameClaims({ name: 'preferred_username' })(upstream).preferred_username).toBe('Ada')
  })

  test('a local subject is namespaced by provider', () => {
    expect(localSubject('entra', 'up-1')).toBe('entra:up-1')
  })
})

describe('account linking', () => {
  const fresh = async () => (await memoryAdapter()) as Adapter

  test('an existing (provider, subject) link is reused', async () => {
    const adapter = await fresh()
    await adapter.identities?.link({ accountId: 'u1', provider: 'entra', subject: 'up-1', claims: {}, linkedAt: new Date() })
    expect(await linkIdentity(adapter, identity())).toEqual({ accountId: 'u1', created: false })
  })

  test('an unknown identity creates an account when allowed to', async () => {
    const adapter = await fresh()
    const result = await linkIdentity(adapter, identity(), { createAccount: async () => 'new-1' })
    expect(result).toEqual({ accountId: 'new-1', created: true })
    expect((await adapter.identities?.find('entra', 'up-1'))?.accountId).toBe('new-1')
  })

  test('an unknown identity with no createAccount is refused rather than silently made', async () => {
    const adapter = await fresh()
    expect(linkIdentity(adapter, identity())).rejects.toThrow(/no local account matches/)
  })

  // NFR-S8: this is the account-takeover primitive, and it must stay off by default.
  test('the default policy never matches on email, even a verified one', async () => {
    const adapter = await fresh()
    const result = await linkIdentity(adapter, identity({ email: 'ada@corp.example', claims: { email_verified: true } }), {
      findByEmail: async () => 'existing-user',
      createAccount: async () => 'new-1'
    })
    expect(result).toEqual({ accountId: 'new-1', created: true })
  })

  test('verified-email matches only when the upstream says the address is verified', async () => {
    const adapter = await fresh()
    const unverified = await linkIdentity(adapter, identity({ email: 'ada@corp.example', claims: { email_verified: false } }), {
      policy: 'verified-email',
      findByEmail: async () => 'existing-user',
      createAccount: async () => 'new-1'
    })
    expect(unverified).toEqual({ accountId: 'new-1', created: true })

    const adapter2 = await fresh()
    const verified = await linkIdentity(adapter2, identity({ email: 'ada@corp.example', claims: { email_verified: true } }), {
      policy: 'verified-email',
      findByEmail: async () => 'existing-user',
      createAccount: async () => 'new-1'
    })
    expect(verified).toEqual({ accountId: 'existing-user', created: false })
  })

  test('interactive refuses to decide and hands the question back', async () => {
    const adapter = await fresh()
    const result = await linkIdentity(adapter, identity({ email: 'ada@corp.example', claims: { email_verified: true } }), {
      policy: 'interactive',
      findByEmail: async () => 'existing-user',
      createAccount: async () => 'new-1'
    })
    expect(result).toEqual({ needsInteraction: 'link', candidate: 'existing-user' })
    expect(await adapter.identities?.find('entra', 'up-1')).toBeUndefined()
  })

  test('an adapter without a FederatedIdentityStore is refused', async () => {
    const adapter = await memoryAdapter({ federation: false })
    expect(linkIdentity(adapter, identity())).rejects.toThrow(/FederatedIdentityStore/)
  })
})
