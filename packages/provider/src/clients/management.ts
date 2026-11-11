import { randomString } from '@oidcraft/core'
import { audit } from '../audit'
import type { ResolvedConfig } from '../config'
import { fapiClientProblems } from '../profile/fapi'
import type { Client } from '../types'
import { clientResponse } from './registration'

export type ManagementClientInput = Omit<Client, 'createdAt' | 'updatedAt' | 'registrationAccessToken'> & {
  clientId?: string
}

const assertProfile = (config: ResolvedConfig, client: Client) => {
  const problems = fapiClientProblems(config, client)
  if (problems.length) throw new Error(`client ${client.clientId} does not meet FAPI 2.0: ${problems.join('; ')} (FR-C21)`)
}

export const clientManagement = (config: ResolvedConfig) => ({
  async list(cursor?: string, limit?: number) {
    if (!config.adapter.clients.list) throw new Error('this adapter cannot list clients')
    return config.adapter.clients.list(cursor, limit)
  },

  async get(clientId: string) {
    return config.adapter.clients.find(clientId)
  },

  async create(input: ManagementClientInput) {
    if (!config.adapter.clients.upsert) throw new Error('this adapter cannot create clients')
    if (input.requirePkce === false && input.tokenEndpointAuthMethod === 'none') {
      throw new Error('a public client cannot opt out of PKCE (FR-C3)')
    }
    const now = new Date()
    const client: Client = {
      ...input,
      clientId: input.clientId ?? randomString(),
      requirePkce: input.requirePkce !== false,
      createdAt: now,
      updatedAt: now
    }
    assertProfile(config, client)
    if (await config.adapter.clients.find(client.clientId)) throw new Error(`client ${client.clientId} already exists`)
    await config.adapter.clients.upsert(client)
    await audit(config, 'client.create', { clientId: client.clientId })
    return client
  },

  async update(clientId: string, patch: Partial<Client>) {
    if (!config.adapter.clients.upsert) throw new Error('this adapter cannot update clients')
    const existing = await config.adapter.clients.find(clientId)
    if (!existing) throw new Error(`client ${clientId} does not exist`)
    const updated = { ...existing, ...patch, clientId, updatedAt: new Date() }
    assertProfile(config, updated)
    await config.adapter.clients.upsert(updated)
    await audit(config, 'client.update', { clientId, detail: { fields: Object.keys(patch) } })
  },

  /** Removing a client without revoking what it holds leaves live tokens behind. */
  async destroy(clientId: string) {
    if (!config.adapter.clients.destroy) throw new Error('this adapter cannot delete clients')
    await config.adapter.clients.destroy(clientId)
    await audit(config, 'client.delete', { clientId })
  },

  /** What a client sees of itself, for an admin screen that mirrors the registration response. */
  describe(client: Client) {
    return clientResponse(config, client)
  }
})
