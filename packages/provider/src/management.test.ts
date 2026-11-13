import { beforeEach, describe, expect, test } from 'bun:test'
import { hashClientSecret } from '@oidcraft/adapter'
import { memoryAdapter } from '@oidcraft/adapter/memory'
import type { AuditEvent, Client, FullAdapter } from './index'
import { createProvider, type Provider } from './provider'

const ISSUER = 'https://op.example.com'

const input = (over: Partial<Client> = {}) => ({
  clientId: 'rp',
  redirectUris: ['https://rp.example.com/cb'],
  grantTypes: ['authorization_code'],
  responseTypes: ['code'],
  scopes: ['openid'],
  tokenEndpointAuthMethod: 'none' as const,
  ...over
})

let adapter: FullAdapter
let provider: Provider
let audit: AuditEvent[]
let delivered: { clientId: string }[]

beforeEach(async () => {
  adapter = await memoryAdapter()
  audit = []
  delivered = []
  provider = createProvider({
    interactionUrl: 'https://op.example.com/interaction',
    issuer: ISSUER,
    adapter,
    onAudit: event => {
      audit.push(event)
    },
    onLogout: notifications => {
      delivered = notifications
    }
  })
})

describe('management', () => {
  // FR-M1: it is a set of functions, not a route, so mounting it is a deliberate act.
  test('is not reachable over HTTP', async () => {
    for (const path of ['/management', '/admin', '/management/clients']) {
      expect((await provider.handle(new Request(`${ISSUER}${path}`))).status).toBe(404)
    }
  })

  test('creates, reads, updates and lists clients', async () => {
    const created = await provider.management.clients.create(input())
    expect(created.clientId).toBe('rp')
    expect((await provider.management.clients.get('rp'))?.redirectUris).toEqual(['https://rp.example.com/cb'])

    await provider.management.clients.update('rp', { clientName: 'Renamed' })
    expect((await provider.management.clients.get('rp'))?.clientName).toBe('Renamed')

    expect((await provider.management.clients.list()).clients.map(client => client.clientId)).toEqual(['rp'])
  })

  // NFR-S11
  test('generates a secret, returns it once, and stores only its hash', async () => {
    const created = await provider.management.clients.create(input({ tokenEndpointAuthMethod: 'client_secret_basic' }))
    expect(created.clientSecret).toBeString()
    const stored = await adapter.clients.find('rp')
    expect(stored?.clientSecret).toBeUndefined()
    expect(stored?.clientSecretHash).toBe(await hashClientSecret(created.clientSecret as string))
    expect(provider.management.clients.describe(stored as Client).client_secret).toBeUndefined()
  })

  test('hashes a secret it is given, on create and on update', async () => {
    const created = await provider.management.clients.create(
      input({ tokenEndpointAuthMethod: 'client_secret_post', clientSecret: 'a-long-enough-client-secret' })
    )
    expect(created.clientSecretHash).toBe(await hashClientSecret('a-long-enough-client-secret'))
    await provider.management.clients.update('rp', { clientSecret: 'another-long-enough-secret' })
    const stored = await adapter.clients.find('rp')
    expect(stored?.clientSecret).toBeUndefined()
    expect(stored?.clientSecretHash).toBe(await hashClientSecret('another-long-enough-secret'))
  })

  test('keeps client_secret_jwt’s secret readable, and will not make one from a hash', async () => {
    const created = await provider.management.clients.create(input({ tokenEndpointAuthMethod: 'client_secret_jwt' }))
    expect((await adapter.clients.find('rp'))?.clientSecret).toBe(created.clientSecret as string)

    await provider.management.clients.create(input({ clientId: 'basic', tokenEndpointAuthMethod: 'client_secret_basic' }))
    await expect(provider.management.clients.update('basic', { tokenEndpointAuthMethod: 'client_secret_jwt' })).rejects.toThrow(
      'cannot give back'
    )
    await provider.management.clients.update('basic', { tokenEndpointAuthMethod: 'client_secret_jwt', clientSecret: 'a-long-enough-key' })
    expect((await adapter.clients.find('basic'))?.clientSecret).toBe('a-long-enough-key')
  })

  test('rotates a secret, which ends the old one', async () => {
    const created = await provider.management.clients.create(input({ tokenEndpointAuthMethod: 'client_secret_basic' }))
    const rotated = await provider.management.clients.rotateSecret('rp')
    expect(rotated).not.toBe(created.clientSecret as string)
    expect((await adapter.clients.find('rp'))?.clientSecretHash).toBe(await hashClientSecret(rotated))
    expect(audit.map(event => event.action)).toContain('client.rotate_secret')

    await provider.management.clients.create(input({ clientId: 'public' }))
    await expect(provider.management.clients.rotateSecret('public')).rejects.toThrow('uses no secret')
  })

  test('generates a client id when none is given', async () => {
    const created = await provider.management.clients.create(input({ clientId: undefined as never }))
    expect(created.clientId).toBeTruthy()
  })

  test('requires PKCE unless the host opts a confidential client out', async () => {
    expect((await provider.management.clients.create(input())).requirePkce).toBe(true)
    const confidential = await provider.management.clients.create(
      input({ clientId: 'rp-2', tokenEndpointAuthMethod: 'client_secret_basic', requirePkce: false })
    )
    expect(confidential.requirePkce).toBe(false)
  })

  test('a public client cannot opt out of PKCE', async () => {
    await expect(provider.management.clients.create(input({ requirePkce: false }))).rejects.toThrow('PKCE')
  })

  // FR-M1: an update is held to what a create is, or the rule is only as strong as the path that skips it.
  test('an update cannot opt a public client out of PKCE either', async () => {
    await provider.management.clients.create(input())
    await expect(provider.management.clients.update('rp', { requirePkce: false })).rejects.toThrow('PKCE')
    expect((await provider.management.clients.get('rp'))?.requirePkce).toBe(true)
  })

  // FR-C18: stored, such a client is a 500 at the token endpoint, where nobody can fix it.
  test('a pairwise client with redirect URIs on several hosts needs a sector_identifier_uri', async () => {
    const pairwise = createProvider({
      interactionUrl: 'https://op.example.com/interaction',
      issuer: ISSUER,
      adapter,
      pairwiseSalt: 'a-long-enough-salt'
    })
    const spread = { subjectType: 'pairwise' as const, redirectUris: ['https://a.example.com/cb', 'https://b.example.com/cb'] }
    await expect(pairwise.management.clients.create(input(spread))).rejects.toThrow('sector_identifier_uri')
    await pairwise.management.clients.create(input({ subjectType: 'pairwise' }))
    await expect(pairwise.management.clients.update('rp', { redirectUris: spread.redirectUris })).rejects.toThrow('sector_identifier_uri')
    await pairwise.management.clients.update('rp', { ...spread, sectorIdentifierUri: 'https://a.example.com/sector.json' })
  })

  test('a pairwise client is refused where the provider issues no pairwise subjects', async () => {
    await expect(provider.management.clients.create(input({ subjectType: 'pairwise' }))).rejects.toThrow('pairwise')
  })

  test('a redirect URI that is not a URL is refused', async () => {
    await expect(provider.management.clients.create(input({ redirectUris: ['not a url'] }))).rejects.toThrow('redirect')
  })

  // FR-T7: a deleted client's tokens answered at UserInfo until they expired, and its consents stayed.
  test('deleting a client revokes the tokens and the grants it holds', async () => {
    await provider.management.clients.create(input())
    await provider.management.clients.create(input({ clientId: 'other' }))
    const token = { payload: {}, expiresAt: new Date(Date.now() + 60_000) }
    const grant = { accountId: 'u1', scopes: ['openid'], claims: [], resources: {}, createdAt: new Date() }
    await adapter.grants.upsert({ ...grant, id: 'g-rp', clientId: 'rp' })
    await adapter.grants.upsert({ ...grant, id: 'g-other', clientId: 'other' })
    await adapter.artifacts.upsert({ ...token, id: 'machine', kind: 'access_token', clientId: 'rp' })
    await adapter.artifacts.upsert({ ...token, id: 'user', kind: 'refresh_token', clientId: 'rp', grantId: 'g-rp' })
    await adapter.artifacts.upsert({ ...token, id: 'theirs', kind: 'access_token', clientId: 'other', grantId: 'g-other' })

    await provider.management.clients.destroy('rp')

    expect(await adapter.artifacts.find('access_token', 'machine')).toBeUndefined()
    expect(await adapter.artifacts.find('refresh_token', 'user')).toBeUndefined()
    expect(await adapter.grants.find('g-rp')).toBeUndefined()
    expect(await adapter.artifacts.find('access_token', 'theirs')).toBeDefined()
    expect(await adapter.grants.find('g-other')).toBeDefined()
  })

  // "Revoked" has to mean the tokens stop working, not just that a row went away.
  test('revoking a grant takes its artifacts with it', async () => {
    await adapter.grants.upsert({
      id: 'g1',
      accountId: 'u1',
      clientId: 'rp',
      scopes: ['openid'],
      claims: [],
      resources: {},
      createdAt: new Date()
    })
    await adapter.artifacts.upsert({
      id: 'at1',
      kind: 'access_token',
      clientId: 'rp',
      grantId: 'g1',
      payload: {},
      expiresAt: new Date(Date.now() + 60_000)
    })

    await provider.management.grants.revoke('g1')
    expect(await adapter.artifacts.find('access_token', 'at1')).toBeUndefined()
    expect(await adapter.grants.find('g1')).toBeUndefined()
  })

  test('lists grants and sessions for an account', async () => {
    await adapter.grants.upsert({
      id: 'g1',
      accountId: 'u1',
      clientId: 'rp',
      scopes: ['openid'],
      claims: [],
      resources: {},
      createdAt: new Date()
    })
    await adapter.sessions.upsert({
      id: 's1',
      accountId: 'u1',
      authTime: new Date(),
      clients: ['rp'],
      expiresAt: new Date(Date.now() + 60_000)
    })

    expect((await provider.management.grants.listForAccount('u1')).map(grant => grant.id)).toEqual(['g1'])
    expect((await provider.management.sessions.listForAccount('u1')).map(session => session.id)).toEqual(['s1'])
  })

  // An operator ending a session must notify clients exactly as a user logging out would.
  test('destroying a session produces the same back-channel notifications as a logout', async () => {
    await provider.management.clients.create(input({ backchannelLogoutUri: 'https://rp.example.com/backchannel' }))
    await adapter.sessions.upsert({
      id: 's1',
      accountId: 'u1',
      authTime: new Date(),
      clients: ['rp'],
      expiresAt: new Date(Date.now() + 60_000)
    })

    const notifications = await provider.management.sessions.destroy('s1')
    expect(notifications).toHaveLength(1)
    expect(delivered).toHaveLength(1)
    expect(await adapter.sessions.find('s1')).toBeUndefined()
  })

  test('destroying an unknown session is a no-op, not a throw', async () => {
    expect(await provider.management.sessions.destroy('nope')).toEqual([])
  })

  // An admin screen has no more business seeing a private key than anyone else does.
  test('keys are listed with public members only', async () => {
    const keys = await provider.management.keys.list()
    expect(keys).toHaveLength(2)
    expect(JSON.stringify(keys)).not.toContain('"d"')
  })

  test('unlinks a linked identity', async () => {
    await adapter.identities.upsert({ accountId: 'u1', provider: 'entra', subject: 'up-1', claims: {}, linkedAt: new Date() })
    expect(await provider.management.identities.listForAccount('u1')).toHaveLength(1)
    await provider.management.identities.unlink('u1', 'entra')
    expect(await provider.management.identities.listForAccount('u1')).toHaveLength(0)
  })

  // FR-M3: the host decides where these go; the library stores none of them.
  test('every write emits an audit event and reads emit none', async () => {
    await provider.management.clients.create(input())
    await provider.management.clients.update('rp', { clientName: 'x' })
    await provider.management.clients.get('rp')
    await provider.management.clients.list()
    await provider.management.clients.destroy('rp')

    expect(audit.map(event => event.action)).toEqual(['client.create', 'client.update', 'client.delete'])
    expect(audit.every(event => event.at instanceof Date)).toBe(true)
  })
})
