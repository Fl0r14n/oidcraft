import type { ResolvedConfig } from './config'
import { OAuthError } from './errors'
import { equals } from './random'
import type { Client } from './types'

export type AuthenticatedClient = { client: Client; method: string }

const unauthorized = (description: string) =>
  new OAuthError('invalid_client', {
    description,
    spec: 'RFC 6749 §2.3, OIDC Core §9',
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

  if (basic && postSecret) throw unauthorized('client credentials were sent both in the Authorization header and the body')

  const clientId = basic?.clientId ?? postId
  if (!clientId) throw unauthorized('no client_id was presented')

  const client = await config.adapter.clients.find(clientId)
  if (!client) throw unauthorized(`unknown client ${clientId}`)

  const method = client.tokenEndpointAuthMethod
  if (!config.clientAuthMethods.includes(method)) {
    throw unauthorized(`client ${clientId} is registered for ${method}, which this provider does not offer`)
  }

  if (method === 'none') {
    if (basic || postSecret) throw unauthorized(`client ${clientId} is public and must not present a secret`)
    return { client, method }
  }

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
