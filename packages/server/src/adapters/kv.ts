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
} from '../adapter'
import type { Artifact, FederatedIdentity, Grant, Seconds, Session } from '../types'

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
 * A complete `Adapter` over a `KvStore` (FR-A3), whose atomic `insert` every single-use rule rests on.
 *
 * Correct, not fast: revocation and the by-account lookups are prefix scans, because a key-value
 * store has no secondary index. A relational adapter must use real columns instead (FR-A5).
 */
export const fromKv = (kv: KvStore, options: FromKvOptions): Adapter => {
  const read = async (key: string) => (await kv.find(key))?.value
  const artifactKey = (kind: string, id: string) => `artifact/${kind}/${id}`
  // Kept apart from the artifact so an upsert cannot overwrite it (FR-T3, NFR-S4).
  const consumedKey = (kind: string, id: string) => `consumed/${kind}/${id}`
  const withConsumption = async (artifact: Artifact) => {
    const consumedAt = await read(consumedKey(artifact.kind, artifact.id))
    const { consumedAt: _, ...rest } = revive(artifact, ['expiresAt'])
    return consumedAt ? { ...rest, consumedAt: new Date(consumedAt) } : rest
  }

  const artifacts: ArtifactStore = {
    async upsert(artifact) {
      const { consumedAt: _, ...stored } = artifact
      const ttl = ttlFrom(artifact.expiresAt)
      await kv.upsert({ key: artifactKey(artifact.kind, artifact.id), value: enc(stored), ttl })
      if (artifact.grantId) await kv.upsert({ key: `grant-index/${artifact.grantId}/${artifact.kind}/${artifact.id}`, value: '', ttl })
      if (typeof artifact.payload.userCode === 'string') {
        await kv.upsert({ key: `user-code/${artifact.payload.userCode}`, value: artifactKey(artifact.kind, artifact.id), ttl })
      }
    },

    async find(kind, id) {
      const artifact = dec<Artifact>(await read(artifactKey(kind, id)))
      if (!artifact) return undefined
      const live = await withConsumption(artifact)
      // FR-T5: an expiry the store missed must still not be served.
      return live.expiresAt.getTime() > Date.now() ? live : undefined
    },

    async findByUserCode(userCode) {
      const pointer = await read(`user-code/${userCode}`)
      if (!pointer) return undefined
      const artifact = dec<Artifact>(await read(pointer))
      return artifact ? withConsumption(artifact) : undefined
    },

    async consume(kind, id) {
      const artifact = dec<Artifact>(await read(artifactKey(kind, id)))
      if (!artifact) return false
      const expiresAt = new Date(artifact.expiresAt)
      if (expiresAt.getTime() <= Date.now()) return false
      return kv.insert({ key: consumedKey(kind, id), value: new Date().toISOString(), ttl: ttlFrom(expiresAt) })
    },

    async destroy(kind, id) {
      await kv.destroy(artifactKey(kind, id))
    },

    async revokeByGrantId(grantId) {
      for await (const { key } of kv.scan(`grant-index/${grantId}/`)) {
        const [, , kind, id] = key.split('/')
        if (kind && id) await kv.destroy(artifactKey(kind, id))
        await kv.destroy(key)
      }
    }
  }

  const clients: ClientStore = {
    async find(clientId) {
      const client = dec<Record<string, unknown>>(await read(`client/${clientId}`))
      return client ? (revive(client, ['createdAt', 'updatedAt']) as never) : undefined
    },
    async upsert(client) {
      await kv.upsert({ key: `client/${client.clientId}`, value: enc(client) })
    },
    async destroy(clientId) {
      await kv.destroy(`client/${clientId}`)
    },
    async list() {
      return { clients: await collect(kv, 'client/', raw => revive(JSON.parse(raw), ['createdAt', 'updatedAt']) as never) }
    }
  }

  const sessions: SessionStore = {
    async find(id) {
      const session = dec<Session>(await read(`session/${id}`))
      if (!session) return undefined
      const live = revive(session, ['authTime', 'expiresAt'])
      return live.expiresAt.getTime() > Date.now() ? live : undefined
    },
    async listForAccount(accountId) {
      const all = await collect(kv, 'session/', raw => revive(JSON.parse(raw) as Session, ['authTime', 'expiresAt']))
      return all.filter(session => session.accountId === accountId && session.expiresAt.getTime() > Date.now())
    },
    async findByUpstreamSession(provider, upstreamSessionId) {
      const all = await collect(kv, 'session/', raw => revive(JSON.parse(raw) as Session, ['authTime', 'expiresAt']))
      return all.filter(session => session.idp === provider && session.upstreamSessionId === upstreamSessionId)
    },
    async upsert(session) {
      await kv.upsert({ key: `session/${session.id}`, value: enc(session), ttl: ttlFrom(session.expiresAt) })
    },
    async destroy(id) {
      await kv.destroy(`session/${id}`)
    }
  }

  const grants: GrantStore = {
    async find(id) {
      const grant = dec<Grant>(await read(`grant/${id}`))
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
      await kv.upsert({ key: `grant/${grant.id}`, value: enc(grant), ...(grant.expiresAt && { ttl: ttlFrom(grant.expiresAt) }) })
    },
    async destroy(id) {
      await kv.destroy(`grant/${id}`)
    }
  }

  const replay: ReplayGuard = {
    async claim(namespace, value, ttl) {
      return kv.insert({ key: `replay/${namespace}/${value}`, value: '1', ttl })
    }
  }

  const identities: FederatedIdentityStore = {
    async find(provider, subject) {
      const identity = dec<FederatedIdentity>(await read(`identity/${provider}/${subject}`))
      return identity ? revive(identity, ['linkedAt']) : undefined
    },
    async listForAccount(accountId) {
      const all = await collect(kv, 'identity/', raw => revive(JSON.parse(raw) as FederatedIdentity, ['linkedAt']))
      return all.filter(identity => identity.accountId === accountId)
    },
    async upsert(identity) {
      await kv.upsert({ key: `identity/${identity.provider}/${identity.subject}`, value: enc(identity) })
    },
    async destroy(provider, subject) {
      await kv.destroy(`identity/${provider}/${subject}`)
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
