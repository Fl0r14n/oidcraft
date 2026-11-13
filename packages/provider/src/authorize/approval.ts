import type { ResolvedConfig } from '../config'
import { OAuthError } from '../errors'

const refuse = (description: string, spec = 'FR-I4') => new OAuthError('invalid_request', { description, spec, status: 400 })

// Every scope asked and no other, as in the browser (FR-I4), and only for the person the session belongs to.
export const checkApproval = async (
  config: ResolvedConfig,
  requested: string[],
  approval: { accountId: string; sessionId: string; scopes: string[] },
  expectedAccountId?: string | undefined
) => {
  const extra = approval.scopes.filter(scope => !requested.includes(scope))
  if (extra.length) throw refuse(`approved scopes were never requested: ${extra.join(', ')}`)
  const missing = requested.filter(scope => !approval.scopes.includes(scope))
  if (missing.length) {
    throw refuse(`an approval must cover every requested scope, or be { denied: true }; it leaves out ${missing.join(', ')}`)
  }
  if (!approval.scopes.includes('openid')) throw refuse('the approval must keep the openid scope')
  if (expectedAccountId !== undefined && approval.accountId !== expectedAccountId) {
    throw refuse('the approving account is not the one this request was made for', 'OIDC CIBA 1.0 §7.1')
  }
  const session = await config.adapter.sessions.find(approval.sessionId)
  if (!session || session.accountId !== approval.accountId) throw refuse('that session does not belong to the approving account', 'FR-I2')
  return approval.scopes
}
