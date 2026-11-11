import type { ResolvedConfig } from '../config'
import { OAuthError } from '../errors'

const refuse = (description: string) => new OAuthError('invalid_request', { description, status: 400 })

/**
 * What the host reports back from an out-of-band approval (device, CIBA). The token carries what
 * was approved, never more than was asked, and only for the person the session belongs to.
 */
export const checkApproval = async (
  config: ResolvedConfig,
  requested: string[],
  approval: { accountId: string; sessionId: string; scopes: string[] },
  expectedAccountId?: string | undefined
) => {
  const extra = approval.scopes.filter(scope => !requested.includes(scope))
  if (extra.length) throw refuse(`approved scopes were never requested: ${extra.join(', ')}`)
  if (!approval.scopes.includes('openid')) throw refuse('the approval must keep the openid scope')
  if (expectedAccountId !== undefined && approval.accountId !== expectedAccountId) {
    throw refuse('the approving account is not the one this request was made for')
  }
  const session = await config.adapter.sessions.find(approval.sessionId)
  if (!session || session.accountId !== approval.accountId) throw refuse('that session does not belong to the approving account')
  return approval.scopes
}
