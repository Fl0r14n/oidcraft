import type { Client } from '@oidcraft/adapter'
import { jwtVerify } from 'jose'
import type { ResolvedConfig } from '../config'
import { OAuthError } from '../errors'
import { CLIENT_SECRET_ALGS, CLIENT_SIGNING_ALGS } from '../keys/algorithms'
import { FAPI_ALGS, FAPI_IAT_SKEW, underFapi } from '../profile/fapi'
import { clientKeySet } from './keys'

export const ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'

/** RFC 7523 §3: the assertion is a bearer credential, so its lifetime must be short (FR-C4). */
const MAX_LIFETIME = 300
const SKEW = 5

const unauthorized = (description: string, spec = 'RFC 7523 §3') =>
  new OAuthError('invalid_client', { description, spec, headers: { 'www-authenticate': 'Basic realm="oidcraft"' } })

/** RFC 10070: the issuer as the sole audience; FAPI 2.0 §5.3.2.1 also wants it as a string, never an array. */
const soleAudience = (aud: unknown, issuer: string, fapi: boolean) =>
  aud === issuer || (!fapi && Array.isArray(aud) && aud.length === 1 && aud[0] === issuer)

// FR-C4: without the audience check, any provider the client talks to could replay its assertion here.
export const verifyClientAssertion = async (config: ResolvedConfig, client: Client, assertion: string) => {
  const method = client.tokenEndpointAuthMethod
  const fapi = underFapi(config, client)

  const key =
    method === 'client_secret_jwt'
      ? client.clientSecret
        ? new TextEncoder().encode(client.clientSecret)
        : (() => {
            throw unauthorized(`client ${client.clientId} has no secret to sign with`)
          })()
      : await clientKeySet(config, client, unauthorized, 'present a private_key_jwt')

  const { payload } = await jwtVerify(assertion, key as never, {
    issuer: client.clientId,
    subject: client.clientId,
    // Confusing the two is how a shared secret gets accepted where a public key was registered.
    algorithms: method === 'client_secret_jwt' ? CLIENT_SECRET_ALGS : fapi ? FAPI_ALGS : CLIENT_SIGNING_ALGS,
    ...(fapi && { clockTolerance: FAPI_IAT_SKEW })
  }).catch(error => {
    if (error instanceof OAuthError) throw error
    throw unauthorized('the client assertion does not verify')
  })

  if (!soleAudience(payload.aud, config.issuer, fapi)) {
    throw fapi
      ? unauthorized('under FAPI 2.0 the assertion audience must be the issuer alone, as a string', 'FAPI 2.0 Security Profile §5.3.2.1')
      : unauthorized('the assertion audience must be the issuer alone, never the token endpoint', 'RFC 10070')
  }
  const jti = payload.jti
  if (typeof jti !== 'string' || !jti) throw unauthorized('the client assertion has no jti', 'RFC 7523 §3')
  if (!payload.exp) throw unauthorized('the client assertion has no exp', 'RFC 7523 §3')
  // From now, not the client's iat: one dated a year ahead would make a year-long assertion look fresh.
  const now = Math.floor(Date.now() / 1000)
  if (payload.iat !== undefined && payload.iat > now + (fapi ? FAPI_IAT_SKEW : SKEW)) {
    throw unauthorized('the client assertion was issued in the future')
  }
  const remaining = payload.exp - now
  if (remaining > MAX_LIFETIME + SKEW) throw unauthorized(`a client assertion may not live longer than ${MAX_LIFETIME} seconds`)

  // NFR-S5: remembered for as long as the assertion verifies, or it is replayable once forgotten.
  // Past exp by up to FAPI's tolerance it still verifies, so it is remembered for that long too.
  // Per client: a client chooses its jti, and must not be able to spend another's in advance.
  const ttl = Math.max(remaining, 0) + (fapi ? FAPI_IAT_SKEW : 0) + SKEW
  if (!(await config.adapter.replay.claim('client-assertion', `${client.clientId} ${jti}`, ttl))) {
    throw unauthorized('this client assertion has already been used')
  }

  return { client, method }
}
