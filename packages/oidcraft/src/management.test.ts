import { beforeEach, describe, expect, test } from 'bun:test'
import { memoryAdapter } from './adapters/memory'
import type { Adapter, AuditEvent, Client } from './index'
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

let adapter: Adapter
let provider: Provider
let audit: AuditEvent[]
let delivered: { clientId: string }[]

beforeEach(async () => {
  adapter = await memoryAdapter()
  audit = []
  delivered = []
  provider = createProvider({
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

  test('generates a client id when none is given', async () => {
    const created = await provider.management.clients.create(input({ clientId: undefined as never }))
    expect(created.clientId).toBeTruthy()
  })

  test('forces PKCE however the client was created', async () => {
    const created = await provider.management.clients.create(input({ requirePkce: false }))
    expect(created.requirePkce).toBe(true)
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
    expect(keys).toHaveLength(1)
    expect(JSON.stringify(keys)).not.toContain('"d"')
  })

  test('unlinks a federated identity', async () => {
    await adapter.identities?.link({ accountId: 'u1', provider: 'entra', subject: 'up-1', claims: {}, linkedAt: new Date() })
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
