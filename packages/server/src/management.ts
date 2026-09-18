import type { ResolvedConfig } from './config'
import { logoutTokens } from './endpoints/end-session'
import { clientResponse } from './endpoints/registration'
import { jwksResponseBody } from './keys'
import { token } from './random'
import type { Client } from './types'

export type ManagementClientInput = Omit<Client, 'createdAt' | 'updatedAt' | 'registrationAccessToken'> & {
  clientId?: string
}

/**
 * The operator-facing surface over clients, grants, sessions and keys (FR-M1).
 *
 * **This performs no authorization.** It is a set of functions, not an HTTP endpoint, precisely so
 * that mounting it is a deliberate act: the host puts it behind its own admin authentication and
 * the library never has to guess who counts as an administrator. Every write emits an audit event
 * the host routes somewhere; the library persists none of them (FR-M3).
 */
export const management = (config: ResolvedConfig) => {
  const audit = (action: string, detail: Record<string, unknown>) => config.onAudit?.({ action, at: new Date(), ...detail })

  return {
    clients: {
      async list(cursor?: string, limit?: number) {
        if (!config.adapter.clients.list) throw new Error('this adapter cannot list clients')
        return config.adapter.clients.list(cursor, limit)
      },

      async get(clientId: string) {
        return config.adapter.clients.find(clientId)
      },

      async create(input: ManagementClientInput) {
        if (!config.adapter.clients.create) throw new Error('this adapter cannot create clients')
        const now = new Date()
        const client: Client = {
          ...input,
          clientId: input.clientId ?? token(16),
          // FR-C3 holds however the client was created.
          requirePkce: true,
          createdAt: now,
          updatedAt: now
        }
        await config.adapter.clients.create(client)
        await audit('client.create', { clientId: client.clientId })
        return client
      },

      async update(clientId: string, patch: Partial<Client>) {
        if (!config.adapter.clients.update) throw new Error('this adapter cannot update clients')
        await config.adapter.clients.update(clientId, { ...patch, updatedAt: new Date() })
        await audit('client.update', { clientId, detail: { fields: Object.keys(patch) } })
      },

      /** Removing a client without revoking what it holds leaves live tokens behind. */
      async destroy(clientId: string) {
        if (!config.adapter.clients.destroy) throw new Error('this adapter cannot delete clients')
        await config.adapter.clients.destroy(clientId)
        await audit('client.delete', { clientId })
      },

      /** What a client sees of itself, for an admin screen that mirrors the registration response. */
      describe(client: Client) {
        return clientResponse(config, client)
      }
    },

    grants: {
      async listForAccount(accountId: string) {
        return config.adapter.grants.listForAccount(accountId)
      },

      /** Revoking consent must take the tokens with it, or "revoked" is a label on nothing. */
      async revoke(grantId: string) {
        await config.adapter.artifacts.revokeByGrantId(grantId)
        await config.adapter.grants.destroy(grantId)
        await audit('grant.revoke', { grantId })
      }
    },

    sessions: {
      async listForAccount(accountId: string) {
        return config.adapter.sessions.findByAccount(accountId)
      },

      /** Ending a session yields the same back-channel notifications an RP-initiated logout would. */
      async destroy(sessionId: string) {
        const session = await config.adapter.sessions.find(sessionId)
        if (!session) return []
        const notifications = await logoutTokens(config, session)
        await config.adapter.sessions.destroy(sessionId)
        await audit('session.destroy', { sessionId, accountId: session.accountId })
        if (notifications.length && config.onLogout) await config.onLogout(notifications)
        return notifications
      }
    },

    keys: {
      /** Public members only: an admin screen has no more business seeing a private key than anyone else. */
      async list() {
        return jwksResponseBody(await config.adapter.keys.active()).keys
      }
    },

    upstreams: {
      /**
       * Read-only on purpose. Upstreams are deployment configuration — an issuer and client
       * credentials — not runtime state, so they are set where the rest of the deployment is set
       * and an operator screen shows what is configured rather than editing it (FR-M2).
       */
      list() {
        return config.upstreams
      }
    },

    identities: {
      async listForAccount(accountId: string) {
        return config.adapter.identities?.listForAccount(accountId) ?? []
      },
      async unlink(accountId: string, provider: string) {
        await config.adapter.identities?.unlink(accountId, provider)
        await audit('identity.unlink', { accountId, detail: { provider } })
      }
    }
  }
}

export type Management = ReturnType<typeof management>
