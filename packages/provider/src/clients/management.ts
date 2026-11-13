import type { Client, Timestamped } from '@oidcraft/adapter'
import { randomString } from '@oidcraft/core'
import { audit } from '../audit'
import type { ResolvedConfig } from '../config'
import { deleteClient } from './delete'
import { clientResponse } from './registration'
import { rotatedSecret, storableSecret } from './secret'
import { clientProblems } from './validate'

export type ManagementClientInput = Omit<Client, keyof Timestamped | 'registrationAccessToken' | 'clientSecretHash'> & {
  clientId?: string
}

const assertValid = (config: ResolvedConfig, client: Client) => {
  const problems = clientProblems(config, client)
  if (problems.length) throw new Error(`client ${client.clientId} cannot be stored: ${problems.join('; ')}`)
}

export const clientManagement = (config: ResolvedConfig) => ({
  async list(cursor?: string, limit?: number) {
    if (!config.adapter.clients.list) throw new Error('this adapter cannot list clients')
    return config.adapter.clients.list(cursor, limit)
  },

  async get(clientId: string) {
    return config.adapter.clients.find(clientId)
  },

  /** The stored client, carrying a generated secret this once: a hashed one cannot be read back (NFR-S11). */
  async create(input: ManagementClientInput) {
    if (!config.adapter.clients.upsert) throw new Error('this adapter cannot create clients')
    const now = new Date()
    const { client, issued } = await storableSecret(
      { ...input, clientId: input.clientId ?? randomString(), requirePkce: input.requirePkce !== false, createdAt: now, updatedAt: now },
      true
    )
    assertValid(config, client)
    if (await config.adapter.clients.find(client.clientId)) throw new Error(`client ${client.clientId} already exists`)
    await config.adapter.clients.upsert(client)
    await audit(config, 'client.create', { clientId: client.clientId })
    return { ...client, ...(issued && { clientSecret: issued }) }
  },

  async update(clientId: string, patch: Partial<Omit<Client, 'clientSecretHash'>>) {
    if (!config.adapter.clients.upsert) throw new Error('this adapter cannot update clients')
    const existing = await config.adapter.clients.find(clientId)
    if (!existing) throw new Error(`client ${clientId} does not exist`)
    const { client: updated } = await storableSecret({ ...existing, ...patch, clientId, updatedAt: new Date() }, false)
    assertValid(config, updated)
    await config.adapter.clients.upsert(updated)
    await audit(config, 'client.update', { clientId, detail: { fields: Object.keys(patch) } })
  },

  /** A new secret for a client that authenticates with one, returned this once; the old one stops working. */
  async rotateSecret(clientId: string) {
    if (!config.adapter.clients.upsert) throw new Error('this adapter cannot update clients')
    const existing = await config.adapter.clients.find(clientId)
    if (!existing) throw new Error(`client ${clientId} does not exist`)
    const { client, issued } = await rotatedSecret({ ...existing, updatedAt: new Date() })
    if (!issued) throw new Error(`client ${clientId} authenticates with ${existing.tokenEndpointAuthMethod}, which uses no secret`)
    await config.adapter.clients.upsert(client)
    await audit(config, 'client.rotate_secret', { clientId })
    return issued
  },

  /** Takes the client's tokens and grants with it (FR-T7). */
  async destroy(clientId: string) {
    if (!config.adapter.clients.destroy) throw new Error('this adapter cannot delete clients')
    await deleteClient(config, clientId)
    await audit(config, 'client.delete', { clientId })
  },

  /** What a client sees of itself, for an admin screen that mirrors the registration response. */
  describe(client: Client) {
    return clientResponse(config, client)
  }
})
