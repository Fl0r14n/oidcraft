import { ASSERTION_TYPE, verifyClientAssertion } from './client-assertion'
import type { ResolvedConfig } from './config'
import { OAuthError } from './errors'
import { equals } from './random'
import type { Client } from './types'

export type AuthenticatedClient = { client: Client; method: string }

/** The assertion names its own client, which is what lets `client_id` be omitted (RFC 7523 §2.2). */
const subjectOf = (assertion: string | null) => {
  if (!assertion) return undefined
  try {
    const payload = assertion.split('.')[1]
    if (!payload) return undefined
    return (JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/'))) as { sub?: string }).sub
  } catch {
    return undefined
  }
}

const unauthorized = (description: string, spec = 'RFC 6749 §2.3, OIDC Core §9') =>
  new OAuthError('invalid_client', {
    description,
    spec,
    headers: { 'www-authenticate': 'Basic realm="oidcraft"' }
  })

const fromBasic = (header: string) => {
  const decoded = atob(header.slice(6))
  const separator = decoded.indexOf(':')
  if (separator < 0) return undefined
  // RFC 6749 §2.3.1: both halves are form-urlencoded before the base64.
  return {
    clientId: decodeURIComponent(decoded.slice(0, separator)),
    clientSecret: decodeURIComponent(decoded.slice(separator + 1))
  }
}

/**
 * Resolves and authenticates the client presenting this request (FR-C4).
 *
 * Credentials in two places at once is rejected rather than resolved by precedence: it is what an
 * attacker does to make the server and an auditing proxy disagree about who is calling.
 */
export const authenticateClient = async (config: ResolvedConfig, form: URLSearchParams, headers: Headers): Promise<AuthenticatedClient> => {
  const authorization = headers.get('authorization')
  const basic = authorization?.toLowerCase().startsWith('basic ') ? fromBasic(authorization) : undefined
  const postId = form.get('client_id')
  const postSecret = form.get('client_secret')
  const assertion = form.get('client_assertion')

  if (basic && postSecret) throw unauthorized('client credentials were sent both in the Authorization header and the body')
  if (assertion && (basic || postSecret)) throw unauthorized('a client assertion was sent alongside a secret')
  if (assertion && form.get('client_assertion_type') !== ASSERTION_TYPE) {
    throw unauthorized(`client_assertion_type must be ${ASSERTION_TYPE}`, 'RFC 7523 §2.2')
  }

  const clientId = basic?.clientId ?? postId ?? subjectOf(assertion)
  if (!clientId) throw unauthorized('no client_id was presented')

  const client = await config.adapter.clients.find(clientId)
  if (!client) throw unauthorized(`unknown client ${clientId}`)

  const method = client.tokenEndpointAuthMethod
  if (!config.clientAuthMethods.includes(method)) {
    throw unauthorized(`client ${clientId} is registered for ${method}, which this provider does not offer`)
  }

  if (method === 'none') {
    if (basic || postSecret || assertion) throw unauthorized(`client ${clientId} is public and must not present a credential`)
    return { client, method }
  }

  if (method === 'private_key_jwt' || method === 'client_secret_jwt') {
    if (!assertion) throw unauthorized(`client ${clientId} must authenticate with ${method}`)
    return verifyClientAssertion(config, client, assertion)
  }

  if (assertion) throw unauthorized(`client ${clientId} is registered for ${method}, not a client assertion`)

  if (method === 'client_secret_basic' || method === 'client_secret_post') {
    const presented = method === 'client_secret_basic' ? basic?.clientSecret : (postSecret ?? undefined)
    if (basic && method === 'client_secret_post') throw unauthorized(`client ${clientId} must authenticate with client_secret_post`)
    if (!basic && method === 'client_secret_basic') throw unauthorized(`client ${clientId} must authenticate with client_secret_basic`)
    if (!presented || !client.clientSecret) throw unauthorized('no client secret was presented')
    if (!(await equals(presented, client.clientSecret))) throw unauthorized('the client secret does not match')
    return { client, method }
  }

  throw unauthorized(`${method} is not implemented yet`)
}
