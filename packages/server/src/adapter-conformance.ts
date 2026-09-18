import { expect, test } from 'bun:test'
import type { Adapter } from './adapter'
import type { Artifact, Client, Grant, Session } from './types'

/**
 * One suite every adapter runs, so memory, Drizzle and Kysely are provably interchangeable rather
 * than merely similar (ARCHITECTURE.md §10). An adapter that passes this is usable; one that does
 * not is a bug in the adapter, not in the core.
 */
export const adapterConformance = (name: string, create: () => Promise<Adapter>) => {
  const soon = (seconds = 60) => new Date(Date.now() + seconds * 1000)

  const client = (clientId: string): Client => ({
    clientId,
    redirectUris: [`https://rp.example.com/${clientId}`],
    grantTypes: ['authorization_code'],
    responseTypes: ['code'],
    scopes: ['openid'],
    tokenEndpointAuthMethod: 'none',
    createdAt: new Date(),
    updatedAt: new Date()
  })

  const artifact = (over: Partial<Artifact> = {}): Artifact => ({
    id: 'a1',
    kind: 'authorization_code',
    clientId: 'c1',
    payload: {},
    expiresAt: soon(),
    ...over
  })

  const session = (over: Partial<Session> = {}): Session => ({
    id: 's1',
    accountId: 'u1',
    authTime: new Date(),
    clients: ['c1'],
    expiresAt: soon(),
    ...over
  })

  const grant = (over: Partial<Grant> = {}): Grant => ({
    id: 'g1',
    accountId: 'u1',
    clientId: 'c1',
    scopes: ['openid'],
    claims: [],
    resources: {},
    createdAt: new Date(),
    ...over
  })

  test(`${name}: a missing record is undefined, never a throw`, async () => {
    const adapter = await create()
    expect(await adapter.clients.find('nope')).toBeUndefined()
    expect(await adapter.artifacts.find('authorization_code', 'nope')).toBeUndefined()
    expect(await adapter.sessions.find('nope')).toBeUndefined()
    expect(await adapter.grants.find('nope')).toBeUndefined()
  })

  test(`${name}: a client round-trips`, async () => {
    const adapter = await create()
    await adapter.clients.create?.(client('c1'))
    const found = await adapter.clients.find('c1')
    expect(found?.clientId).toBe('c1')
    expect(found?.redirectUris).toEqual(['https://rp.example.com/c1'])
    expect(found?.createdAt).toBeInstanceOf(Date)
  })

  test(`${name}: destroying a client removes it`, async () => {
    const adapter = await create()
    await adapter.clients.create?.(client('c1'))
    await adapter.clients.destroy?.('c1')
    expect(await adapter.clients.find('c1')).toBeUndefined()
  })

  test(`${name}: an artifact round-trips with its dates intact`, async () => {
    const adapter = await create()
    await adapter.artifacts.upsert(artifact())
    const found = await adapter.artifacts.find('authorization_code', 'a1')
    expect(found?.id).toBe('a1')
    expect(found?.expiresAt).toBeInstanceOf(Date)
  })

  test(`${name}: kind is part of the identity, so two kinds may share an id`, async () => {
    const adapter = await create()
    await adapter.artifacts.upsert(artifact({ id: 'same', kind: 'authorization_code' }))
    await adapter.artifacts.upsert(artifact({ id: 'same', kind: 'refresh_token' }))
    expect((await adapter.artifacts.find('authorization_code', 'same'))?.kind).toBe('authorization_code')
    expect((await adapter.artifacts.find('refresh_token', 'same'))?.kind).toBe('refresh_token')
  })

  // FR-T5: storage enforces expiry, so a missed prune cycle still cannot serve a dead token.
  test(`${name}: an expired artifact is never served`, async () => {
    const adapter = await create()
    await adapter.artifacts.upsert(artifact({ expiresAt: new Date(Date.now() - 1000) }))
    expect(await adapter.artifacts.find('authorization_code', 'a1')).toBeUndefined()
  })

  // FR-T4: consuming marks it; replaying a consumed code is what revokes the grant.
  test(`${name}: consume marks the artifact without destroying it`, async () => {
    const adapter = await create()
    await adapter.artifacts.upsert(artifact())
    await adapter.artifacts.consume('authorization_code', 'a1')
    expect((await adapter.artifacts.find('authorization_code', 'a1'))?.consumedAt).toBeInstanceOf(Date)
  })

  test(`${name}: destroy removes the artifact`, async () => {
    const adapter = await create()
    await adapter.artifacts.upsert(artifact())
    await adapter.artifacts.destroy('authorization_code', 'a1')
    expect(await adapter.artifacts.find('authorization_code', 'a1')).toBeUndefined()
  })

  // The query the protocol needs most and a blob store handles worst (FR-A5).
  test(`${name}: revokeByGrantId removes every artifact of that grant and nothing else`, async () => {
    const adapter = await create()
    await adapter.artifacts.upsert(artifact({ id: 'a1', kind: 'authorization_code', grantId: 'g1' }))
    await adapter.artifacts.upsert(artifact({ id: 'a2', kind: 'refresh_token', grantId: 'g1' }))
    await adapter.artifacts.upsert(artifact({ id: 'a3', kind: 'refresh_token', grantId: 'g2' }))
    await adapter.artifacts.revokeByGrantId('g1')
    expect(await adapter.artifacts.find('authorization_code', 'a1')).toBeUndefined()
    expect(await adapter.artifacts.find('refresh_token', 'a2')).toBeUndefined()
    expect((await adapter.artifacts.find('refresh_token', 'a3'))?.id).toBe('a3')
  })

  test(`${name}: a device code is reachable by its user code`, async () => {
    const adapter = await create()
    await adapter.artifacts.upsert(artifact({ id: 'd1', kind: 'device_code', payload: { userCode: 'WDJB-MJHT' } }))
    expect((await adapter.artifacts.findByUserCode?.('WDJB-MJHT'))?.id).toBe('d1')
  })

  test(`${name}: sessions round-trip and list by account`, async () => {
    const adapter = await create()
    await adapter.sessions.upsert(session())
    await adapter.sessions.upsert(session({ id: 's2' }))
    await adapter.sessions.upsert(session({ id: 's3', accountId: 'u2' }))
    expect((await adapter.sessions.findByAccount('u1')).map(s => s.id).sort()).toEqual(['s1', 's2'])
  })

  test(`${name}: an expired session is never served`, async () => {
    const adapter = await create()
    await adapter.sessions.upsert(session({ expiresAt: new Date(Date.now() - 1000) }))
    expect(await adapter.sessions.find('s1')).toBeUndefined()
  })

  // FR-F8: upstream back-channel logout arrives keyed by the upstream session, not ours.
  test(`${name}: sessions are reachable by their upstream session`, async () => {
    const adapter = await create()
    await adapter.sessions.upsert(session({ idp: 'entra', upstreamSessionId: 'up-1' }))
    await adapter.sessions.upsert(session({ id: 's2', idp: 'entra', upstreamSessionId: 'up-2' }))
    const found = await adapter.sessions.findByUpstreamSession?.('entra', 'up-1')
    expect(found?.map(s => s.id)).toEqual(['s1'])
  })

  test(`${name}: a grant is reachable by account and client`, async () => {
    const adapter = await create()
    await adapter.grants.upsert(grant())
    expect((await adapter.grants.findByAccountAndClient('u1', 'c1'))?.id).toBe('g1')
    expect(await adapter.grants.findByAccountAndClient('u1', 'other')).toBeUndefined()
    expect((await adapter.grants.listForAccount('u1')).map(g => g.id)).toEqual(['g1'])
  })

  // NFR-S5: the guard is what makes a jti or a DPoP proof one-shot.
  test(`${name}: the replay guard admits a value once`, async () => {
    const adapter = await create()
    expect(await adapter.replay.claim('jti', 'abc', 60)).toBe(true)
    expect(await adapter.replay.claim('jti', 'abc', 60)).toBe(false)
    expect(await adapter.replay.claim('dpop', 'abc', 60)).toBe(true)
  })

  test(`${name}: keys are available and carry an algorithm`, async () => {
    const adapter = await create()
    const keys = await adapter.keys.active()
    expect(keys.length).toBeGreaterThan(0)
    expect(keys[0]?.alg).toBeTruthy()
    expect(keys[0]?.kid).toBeTruthy()
  })

  // FR-F5: linking is by (provider, subject) and nothing else.
  test(`${name}: a federated identity links and unlinks by provider and subject`, async () => {
    const adapter = await create()
    if (!adapter.identities) return
    await adapter.identities.link({ accountId: 'u1', provider: 'google', subject: 'g-1', claims: {}, linkedAt: new Date() })
    expect((await adapter.identities.find('google', 'g-1'))?.accountId).toBe('u1')
    expect(await adapter.identities.find('entra', 'g-1')).toBeUndefined()
    await adapter.identities.unlink('u1', 'google')
    expect(await adapter.identities.find('google', 'g-1')).toBeUndefined()
  })
}
