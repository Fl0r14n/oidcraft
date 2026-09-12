import { createLocalJWKSet, type JSONWebKeySet, jwtVerify } from 'jose'
import type { ResolvedConfig } from './config'
import { OAuthError } from './errors'
import type { Client } from './types'

/** RFC 9101 §8.2: `none` would make the object unauthenticated, which is the whole point of it. */
const FORBIDDEN_ALGS = ['none', 'HS256', 'HS384', 'HS512']

/** Parameters that must agree with what was sent outside the object, when present (§6.1). */
const MUST_AGREE = ['client_id', 'response_type']

const invalid = (description: string, spec = 'RFC 9101 §6.1') => new OAuthError('invalid_request', { description, spec })

const keySetFor = async (config: ResolvedConfig, client: Client) => {
  if (client.jwks) return createLocalJWKSet(client.jwks as unknown as JSONWebKeySet)
  if (client.jwksUri) {
    // Fetching it here would be outbound I/O in the core, to a URL the client chose (FR-A1).
    if (!config.resolveClientJwks) {
      throw invalid(
        `client ${client.clientId} registered a jwks_uri but no resolveClientJwks was configured; the core does not fetch it itself`,
        'ARCHITECTURE.md §3.2'
      )
    }
    return createLocalJWKSet((await config.resolveClientJwks(client)) as unknown as JSONWebKeySet)
  }
  throw invalid(`client ${client.clientId} has no keys registered, so it cannot sign a request object`)
}

/**
 * Verifies a JAR request object and folds its parameters into the request (RFC 9101).
 *
 * The object's parameters win: that is the point of signing them. Anything outside it is advisory,
 * and the few that must agree are checked rather than quietly overridden.
 */
export const applyRequestObject = async (config: ResolvedConfig, client: Client, params: URLSearchParams) => {
  const jwt = params.get('request')
  if (!jwt) return params

  const { payload, protectedHeader } = await jwtVerify(jwt, await keySetFor(config, client), {
    issuer: client.clientId,
    audience: config.issuer
  }).catch(error => {
    if (error instanceof OAuthError) throw error
    throw invalid('the request object does not verify against the keys registered for this client')
  })

  if (FORBIDDEN_ALGS.includes(protectedHeader.alg))
    throw invalid(`${protectedHeader.alg} is not acceptable for a request object`, 'RFC 9101 §8.2')
  if ('request' in payload || 'request_uri' in payload)
    throw invalid('a request object may not contain request or request_uri', 'RFC 9101 §6.1')

  for (const name of MUST_AGREE) {
    const outside = params.get(name)
    const inside = payload[name]
    if (outside !== null && inside !== undefined && outside !== inside) {
      throw invalid(`${name} in the request object does not match the one sent alongside it`)
    }
  }

  const merged = new URLSearchParams(params)
  merged.delete('request')
  for (const [name, value] of Object.entries(payload)) {
    if (['iss', 'aud', 'exp', 'nbf', 'iat', 'jti'].includes(name)) continue
    if (value !== undefined && value !== null) merged.set(name, String(value))
  }
  return merged
}
