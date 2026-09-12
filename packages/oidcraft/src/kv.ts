import type {
  AccountStore,
  Adapter,
  ArtifactStore,
  ClientStore,
  FederatedIdentityStore,
  GrantStore,
  KeyStore,
  KvStore,
  ReplayGuard,
  SessionStore
} from './adapter'
import type { Artifact, FederatedIdentity, Grant, Seconds, Session } from './types'

export type FromKvOptions = {
  keys: KeyStore
  accounts: AccountStore
  /** Without one, `identities` is absent and a brokering deployment will not start (FR-F5). */
  federation?: boolean
}

const enc = (value: unknown) => JSON.stringify(value)

const dec = <T>(raw: string | undefined): T | undefined => (raw === undefined ? undefined : (JSON.parse(raw) as T))

const revive = <T>(value: T, dates: (keyof T & string)[]) => {
  const record = value as Record<string, unknown>
  for (const field of dates) {
    if (typeof record[field] === 'string') record[field] = new Date(record[field] as string)
  }
  return value
}

const ttlFrom = (expiresAt: Date): Seconds => Math.max(1, Math.ceil((expiresAt.getTime() - Date.now()) / 1000))

const collect = async <T>(kv: KvStore, prefix: string, revived: (raw: string) => T) => {
  const out: T[] = []
  for await (const { value } of kv.scan(prefix)) out.push(revived(value))
  return out
}

/**
 * A complete `Adapter` over four key-value methods (FR-A3).
 *
 * Correct, not fast: revocation and the by-account lookups are prefix scans, because a key-value
 * store has no secondary index. A relational adapter must use real columns instead (FR-A5).
 */
export const fromKv = (kv: KvStore, options: FromKvOptions): Adapter => {
  const artifactKey = (kind: string, id: string) => `artifact/${kind}/${id}`

  const artifacts: ArtifactStore = {
    async upsert(artifact) {
      await kv.set(artifactKey(artifact.kind, artifact.id), enc(artifact), ttlFrom(artifact.expiresAt))
      if (artifact.grantId) await kv.set(`grant-index/${artifact.grantId}/${artifact.kind}/${artifact.id}`, '', ttlFrom(artifact.expiresAt))
      if (typeof artifact.payload.userCode === 'string') {
        await kv.set(`user-code/${artifact.payload.userCode}`, artifactKey(artifact.kind, artifact.id), ttlFrom(artifact.expiresAt))
      }
    },

    async find(kind, id) {
      const artifact = dec<Artifact>(await kv.get(artifactKey(kind, id)))
      if (!artifact) return undefined
      const live = revive(artifact, ['expiresAt', 'consumedAt'])
      // FR-T5: an expiry the store missed must still not be served.
      return live.expiresAt.getTime() > Date.now() ? live : undefined
    },

    async findByUserCode(userCode) {
      const pointer = await kv.get(`user-code/${userCode}`)
      if (!pointer) return undefined
      const artifact = dec<Artifact>(await kv.get(pointer))
      return artifact ? revive(artifact, ['expiresAt', 'consumedAt']) : undefined
    },

    async consume(kind, id) {
      const artifact = dec<Artifact>(await kv.get(artifactKey(kind, id)))
      if (!artifact) return
      artifact.consumedAt = new Date()
      await kv.set(artifactKey(kind, id), enc(artifact), ttlFrom(new Date(artifact.expiresAt)))
    },

    async destroy(kind, id) {
      await kv.delete(artifactKey(kind, id))
    },

    async revokeByGrantId(grantId) {
      for await (const { key } of kv.scan(`grant-index/${grantId}/`)) {
        const [, , kind, id] = key.split('/')
        if (kind && id) await kv.delete(artifactKey(kind, id))
        await kv.delete(key)
      }
    }
  }

  const clients: ClientStore = {
    async find(clientId) {
      const client = dec<Record<string, unknown>>(await kv.get(`client/${clientId}`))
      return client ? (revive(client, ['createdAt', 'updatedAt']) as never) : undefined
    },
    async create(client) {
      await kv.set(`client/${client.clientId}`, enc(client))
    },
    async update(clientId, patch) {
      const existing = dec<Record<string, unknown>>(await kv.get(`client/${clientId}`))
      if (!existing) return
      await kv.set(`client/${clientId}`, enc({ ...existing, ...patch, updatedAt: new Date() }))
    },
    async destroy(clientId) {
      await kv.delete(`client/${clientId}`)
    },
    async list() {
      return { clients: await collect(kv, 'client/', raw => revive(JSON.parse(raw), ['createdAt', 'updatedAt']) as never) }
    }
  }

  const sessions: SessionStore = {
    async find(id) {
      const session = dec<Session>(await kv.get(`session/${id}`))
      if (!session) return undefined
      const live = revive(session, ['authTime', 'expiresAt'])
      return live.expiresAt.getTime() > Date.now() ? live : undefined
    },
    async findByAccount(accountId) {
      const all = await collect(kv, 'session/', raw => revive(JSON.parse(raw) as Session, ['authTime', 'expiresAt']))
      return all.filter(session => session.accountId === accountId && session.expiresAt.getTime() > Date.now())
    },
    async findByUpstreamSession(provider, upstreamSessionId) {
      const all = await collect(kv, 'session/', raw => revive(JSON.parse(raw) as Session, ['authTime', 'expiresAt']))
      return all.filter(session => session.idp === provider && session.upstreamSessionId === upstreamSessionId)
    },
    async upsert(session) {
      await kv.set(`session/${session.id}`, enc(session), ttlFrom(session.expiresAt))
    },
    async destroy(id) {
      await kv.delete(`session/${id}`)
    }
  }

  const grants: GrantStore = {
    async find(id) {
      const grant = dec<Grant>(await kv.get(`grant/${id}`))
      return grant ? revive(grant, ['createdAt', 'expiresAt']) : undefined
    },
    async findByAccountAndClient(accountId, clientId) {
      const all = await collect(kv, 'grant/', raw => revive(JSON.parse(raw) as Grant, ['createdAt', 'expiresAt']))
      return all.find(grant => grant.accountId === accountId && grant.clientId === clientId)
    },
    async listForAccount(accountId) {
      const all = await collect(kv, 'grant/', raw => revive(JSON.parse(raw) as Grant, ['createdAt', 'expiresAt']))
      return all.filter(grant => grant.accountId === accountId)
    },
    async upsert(grant) {
      await kv.set(`grant/${grant.id}`, enc(grant), grant.expiresAt ? ttlFrom(grant.expiresAt) : undefined)
    },
    async destroy(id) {
      await kv.delete(`grant/${id}`)
    }
  }

  const replay: ReplayGuard = {
    async claim(namespace, value, ttl) {
      const key = `replay/${namespace}/${value}`
      if ((await kv.get(key)) !== undefined) return false
      await kv.set(key, '1', ttl)
      return true
    }
  }

  const identities: FederatedIdentityStore = {
    async find(provider, subject) {
      const identity = dec<FederatedIdentity>(await kv.get(`identity/${provider}/${subject}`))
      return identity ? revive(identity, ['linkedAt']) : undefined
    },
    async listForAccount(accountId) {
      const all = await collect(kv, 'identity/', raw => revive(JSON.parse(raw) as FederatedIdentity, ['linkedAt']))
      return all.filter(identity => identity.accountId === accountId)
    },
    async link(identity) {
      await kv.set(`identity/${identity.provider}/${identity.subject}`, enc(identity))
    },
    async unlink(accountId, provider) {
      for await (const { key, value } of kv.scan(`identity/${provider}/`)) {
        if ((JSON.parse(value) as FederatedIdentity).accountId === accountId) await kv.delete(key)
      }
    }
  }

  return {
    clients,
    artifacts,
    sessions,
    grants,
    accounts: options.accounts,
    keys: options.keys,
    replay,
    ...(options.federation !== false && { identities })
  }
}
