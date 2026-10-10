import { audit } from '../audit'
import type { ResolvedConfig } from '../config'
import { logoutTokens } from './logout'

export const sessionManagement = (config: ResolvedConfig) => ({
  async listForAccount(accountId: string) {
    return config.adapter.sessions.listForAccount(accountId)
  },

  /** Ending a session yields the same back-channel notifications an RP-initiated logout would. */
  async destroy(sessionId: string) {
    const session = await config.adapter.sessions.find(sessionId)
    if (!session) return []
    const notifications = await logoutTokens(config, session)
    await config.adapter.sessions.destroy(sessionId)
    await audit(config, 'session.destroy', { sessionId, accountId: session.accountId })
    if (notifications.length && config.onLogout) await config.onLogout(notifications)
    return notifications
  }
})
