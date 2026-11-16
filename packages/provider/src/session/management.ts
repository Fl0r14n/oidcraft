import { audit } from '../audit'
import type { ResolvedConfig } from '../config'
import { settled } from '../hooks'
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
    await settled([
      () => audit(config, 'session.destroy', { sessionId, accountId: session.accountId }),
      () => notifications.length && config.onLogout?.(notifications),
      () => config.onSessionEnd?.(session, 'management')
    ])
    return notifications
  }
})
