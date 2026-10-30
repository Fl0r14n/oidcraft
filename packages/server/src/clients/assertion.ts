import { createLocalJWKSet, type JSONWebKeySet, jwtVerify } from 'jose'
import type { ResolvedConfig } from '../config'
import { OAuthError } from '../errors'
import { CLIENT_SECRET_ALGS, CLIENT_SIGNING_ALGS } from '../keys/algorithms'
import { FAPI_ALGS, FAPI_IAT_SKEW, FAPI_NBF_MAX_AGE, underFapi } from '../profile/fapi'
import type { Client } from '../types'

export const ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'

/** RFC 7523 §3: the assertion is a bearer credential, so its lifetime must be short (FR-C4). */
const MAX_LIFETIME = 300
const SKEW = 5

const unauthorized = (description: string, spec = 'RFC 7523 §3') =>
  new OAuthError('invalid_client', { description, spec, headers: { 'www-authenticate': 'Basic realm="oidcraft"' } })

const keysFor = async (config: ResolvedConfig, client: Client) => {
  if (client.jwks) return createLocalJWKSet(client.jwks as unknown as JSONWebKeySet)
  if (client.jwksUri) {
    if (!config.resolveClientJwks) {
      throw unauthorized(
        `client ${client.clientId} registered a jwks_uri but no resolveClientJwks was configured; the core does not fetch it itself`,
        'ARCHITECTURE.md §3.2'
      )
    }
    return createLocalJWKSet((await config.resolveClientJwks(client)) as unknown as JSONWebKeySet)
  }
  throw unauthorized(`client ${client.clientId} has no keys registered, so it cannot present a private_key_jwt`)
}

/**
 * Verifies a JWT client assertion (RFC 7523 §3, OIDC Core §9).
 *
 * The audience is the thing that makes this safe to hand over: an assertion made out to this
 * provider cannot be replayed at another one, and the `jti` guard stops it being replayed here.
 * Accepting an assertion with no audience check would turn every provider a client talks to into
 * an oracle able to impersonate it everywhere else.
 */
export const verifyClientAssertion = async (config: ResolvedConfig, client: Client, assertion: string) => {
  const method = client.tokenEndpointAuthMethod
  const fapi = underFapi(config, client)
  // OIDC Core §9 says the audience SHOULD be the token endpoint; FAPI 2.0 accepts the issuer alone (§5.3.2.1).
  const audience = fapi ? [config.issuer] : [config.issuer, `${config.issuer}${config.routes.token}`]

  const key =
    method === 'client_secret_jwt'
      ? client.clientSecret
        ? new TextEncoder().encode(client.clientSecret)
        : (() => {
            throw unauthorized(`client ${client.clientId} has no secret to sign with`)
          })()
      : await keysFor(config, client)

  const { payload } = await jwtVerify(assertion, key as never, {
    issuer: client.clientId,
    subject: client.clientId,
    audience,
    // Confusing the two is how a shared secret gets accepted where a public key was registered.
    algorithms: method === 'client_secret_jwt' ? CLIENT_SECRET_ALGS : fapi ? FAPI_ALGS : CLIENT_SIGNING_ALGS,
    ...(fapi && { clockTolerance: FAPI_IAT_SKEW })
  }).catch(error => {
    if (error instanceof OAuthError) throw error
    throw unauthorized('the client assertion does not verify')
  })

  const jti = payload.jti
  if (typeof jti !== 'string' || !jti) throw unauthorized('the client assertion has no jti', 'RFC 7523 §3')
  if (!payload.exp) throw unauthorized('the client assertion has no exp', 'RFC 7523 §3')
  // Measured from now, not from the client's own iat: an iat it chose a year ahead would otherwise
  // make a year-long assertion look five minutes old.
  const now = Math.floor(Date.now() / 1000)
  if (payload.iat !== undefined && payload.iat > now + (fapi ? FAPI_IAT_SKEW : SKEW)) {
    throw unauthorized('the client assertion was issued in the future')
  }
  if (fapi && payload.nbf !== undefined && payload.nbf < now - FAPI_NBF_MAX_AGE) {
    throw unauthorized(`the client assertion's nbf is more than ${FAPI_NBF_MAX_AGE} seconds old`, 'FAPI 2.0 Security Profile §5.3.2.1')
  }
  const remaining = payload.exp - now
  if (remaining > MAX_LIFETIME + SKEW) throw unauthorized(`a client assertion may not live longer than ${MAX_LIFETIME} seconds`)

  // NFR-S5: remembered for as long as the assertion verifies, or it is replayable once forgotten.
  if (!(await config.adapter.replay.claim('client-assertion', jti, remaining + SKEW))) {
    throw unauthorized('this client assertion has already been used')
  }

  return { client, method }
}
