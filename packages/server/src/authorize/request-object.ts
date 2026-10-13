import { createLocalJWKSet, type JSONWebKeySet, jwtVerify } from 'jose'
import type { ResolvedConfig } from '../config'
import { OAuthError } from '../errors'
import { CLIENT_SIGNING_ALGS } from '../keys/algorithms'
import type { Client } from '../types'

/** RFC 9101 §8.2: `none` would make the object unauthenticated, which is the whole point of it. */

/**
 * Parameters that must agree with what was sent outside the object, when present (§6.1). They are
 * also the only ones taken from outside: OIDC Core §6.1 requires them in the query even when the
 * object carries them, so an object that omits them still names its client and response type.
 */
const MUST_AGREE = ['client_id', 'response_type']

const JWT_CLAIMS = ['iss', 'aud', 'exp', 'nbf', 'iat', 'jti']

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
 * Only the object's parameters are used (RFC 9101 §5): one left out of it is absent, not
 * something the unsigned query may supply — otherwise an attacker adds a `code_challenge` or a
 * `prompt` the client never signed. The two that must agree are checked rather than overridden.
 */
export const applyRequestObject = async (config: ResolvedConfig, client: Client, params: URLSearchParams) => {
  const jwt = params.get('request')
  if (!jwt) return params

  const { payload } = await jwtVerify(jwt, await keySetFor(config, client), {
    issuer: client.clientId,
    audience: config.issuer,
    // RFC 9101 §8.2: never none, never a shared secret; exactly what discovery advertises.
    algorithms: CLIENT_SIGNING_ALGS
  }).catch(error => {
    if (error instanceof OAuthError) throw error
    throw invalid('the request object does not verify against the keys registered for this client')
  })

  if ('request' in payload || 'request_uri' in payload)
    throw invalid('a request object may not contain request or request_uri', 'RFC 9101 §6.1')

  for (const name of MUST_AGREE) {
    const outside = params.get(name)
    const inside = payload[name]
    if (outside !== null && inside !== undefined && outside !== inside) {
      throw invalid(`${name} in the request object does not match the one sent alongside it`)
    }
  }

  const resolved = new URLSearchParams()
  for (const name of MUST_AGREE) {
    const outside = params.get(name)
    if (outside !== null) resolved.set(name, outside)
  }
  for (const [name, value] of Object.entries(payload)) {
    if (JWT_CLAIMS.includes(name) || value === undefined || value === null) continue
    // A JSON claim such as authorization_details travels as JSON in the query form (RFC 9396 §3).
    resolved.set(name, typeof value === 'string' ? value : JSON.stringify(value))
  }
  return resolved
}
