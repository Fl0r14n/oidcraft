import type { Client } from '@oidcraft/adapter'
import { jwtVerify } from 'jose'
import { clientKeySet } from '../clients/keys'
import type { ResolvedConfig } from '../config'
import { OAuthError } from '../errors'
import { CLIENT_SIGNING_ALGS } from '../keys/algorithms'
import { FAPI_ALGS, underFapi } from '../profile/fapi'

// Must agree when present, and the only ones taken from outside: OIDC Core §6.1 requires them in the query too.
const MUST_AGREE = ['client_id', 'response_type']

const JWT_CLAIMS = ['iss', 'aud', 'exp', 'nbf', 'iat', 'jti']

/** FR-C12: a request object rides in a URL, so it lands in logs and history; a bounded lifetime bounds its replay. */
const MAX_LIFETIME = 3600
const SKEW = 5
const TYPE = 'oauth-authz-req+jwt'

const invalid = (description: string, spec = 'RFC 9101 §6.1') => new OAuthError('invalid_request', { description, spec })

// RFC 9101 §5: only the object's parameters count, or the unsigned query could add a `code_challenge` the client never signed.
export const applyRequestObject = async (config: ResolvedConfig, client: Client, params: URLSearchParams) => {
  const jwt = params.get('request')
  if (!jwt) return params

  const { payload, protectedHeader } = await jwtVerify(jwt, await clientKeySet(config, client, invalid, 'sign a request object'), {
    issuer: client.clientId,
    audience: config.issuer,
    // RFC 9101 §8.2: never none, never a shared secret; exactly what discovery advertises.
    algorithms: underFapi(config, client) ? FAPI_ALGS : CLIENT_SIGNING_ALGS,
    requiredClaims: ['exp'],
    clockTolerance: SKEW
  }).catch(error => {
    if (error instanceof OAuthError) throw error
    throw invalid('the request object does not verify against the keys registered for this client, or has no exp, or has expired')
  })

  // RFC 9101 §4 asks for the type, and many clients omit it; one that names another is refused.
  if (protectedHeader.typ !== undefined && protectedHeader.typ !== TYPE) throw invalid(`a request object's typ is ${TYPE}`, 'RFC 9101 §4')
  const now = Math.floor(Date.now() / 1000)
  if (typeof payload.iat === 'number' && payload.iat > now + SKEW)
    throw invalid('the request object was issued in the future', 'RFC 9101 §10.8')
  const start = typeof payload.nbf === 'number' ? payload.nbf : typeof payload.iat === 'number' ? payload.iat : now
  if ((payload.exp as number) - Math.min(start, now) > MAX_LIFETIME) {
    throw invalid(`a request object may live at most ${MAX_LIFETIME} seconds`, 'RFC 9101 §10.8')
  }

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
    // A parameter the query form repeats, such as resource (RFC 8707 §2), arrives as an array of strings.
    if (Array.isArray(value) && value.length && value.every(each => typeof each === 'string')) {
      for (const each of value) resolved.append(name, each)
      continue
    }
    // A JSON claim such as authorization_details travels as JSON in the query form (RFC 9396 §3).
    resolved.set(name, typeof value === 'string' ? value : JSON.stringify(value))
  }
  return resolved
}
