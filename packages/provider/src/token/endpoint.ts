import type { Client } from '@oidcraft/adapter'
import { CIBA_GRANT_TYPE, redeemCibaRequest } from '../authorize/ciba'
import { DEVICE_CODE_GRANT_TYPE, redeemDeviceCode } from '../authorize/device'
import { proofOptions, verifyDpopProof } from '../binding/dpop'
import { authenticateClient } from '../clients/authenticate'
import type { ResolvedConfig } from '../config'
import type { ClientCertificate } from '../context'
import type { Caller } from '../cors'
import { supportedGrantTypes } from '../discovery'
import { OAuthError } from '../errors'
import { readForm } from '../form'
import { underFapi } from '../profile/fapi'
import { redeemClientCredentials } from './client-credentials'
import { redeemAuthorizationCode, redeemRefreshToken } from './code'
import { redeemSubjectToken, TOKEN_EXCHANGE_GRANT_TYPE } from './exchange'
import { JWT_BEARER_GRANT_TYPE, redeemIdentityAssertion } from './identity-assertion'

const NO_STORE = { 'cache-control': 'no-store', pragma: 'no-cache' }

/** A client may always offer a proof; one registered for bound tokens must (RFC 9449 §5), and never gets a bearer token instead (FR-C13). */
const bindingFor = async (config: ResolvedConfig, client: Client, request: Request) => {
  if (!config.features.dpop) {
    if (!client.dpopBoundAccessTokens) return undefined
    throw new OAuthError('invalid_client', {
      description: `client ${client.clientId} is registered for DPoP-bound tokens, which this provider does not issue`,
      spec: 'FR-C13'
    })
  }
  const offered = request.headers.has('dpop')
  if (!offered) {
    if (!client.dpopBoundAccessTokens) return undefined
    throw new OAuthError('invalid_dpop_proof', {
      description: `client ${client.clientId} is registered for DPoP-bound tokens and presented no proof`,
      spec: 'RFC 9449 §5'
    })
  }
  return (await verifyDpopProof(config, request, proofOptions(config, request, client.clientId, client))).jkt
}

export const tokenEndpoint = async (
  config: ResolvedConfig,
  request: Request,
  certificate?: ClientCertificate | undefined,
  caller: Caller = {}
) => {
  const form = await readForm(request)
  const { client } = await authenticateClient(config, form, request.headers, certificate, caller)

  const grantType = form.get('grant_type')
  if (!grantType) throw new OAuthError('invalid_request', { description: 'grant_type is required', spec: 'RFC 6749 §5.2' })
  // FR-C6: what discovery does not advertise is not dispatched, whatever a stored client lists.
  if (!supportedGrantTypes(config).includes(grantType)) {
    throw new OAuthError('unsupported_grant_type', { description: `${grantType} is not supported`, spec: 'RFC 6749 §5.2' })
  }
  if (!client.grantTypes.includes(grantType)) {
    throw new OAuthError('unauthorized_client', {
      description: `client ${client.clientId} may not use grant_type ${grantType}`,
      spec: 'RFC 6749 §5.2'
    })
  }

  const jkt = await bindingFor(config, client, request)
  const fapi = underFapi(config, client)
  // RFC 8705 §3: binding to the certificate already presented costs nothing and makes a stolen token useless.
  const binding = { jkt, x5t: client.certificateBoundAccessTokens || fapi ? certificate?.thumbprint : undefined }
  if (client.certificateBoundAccessTokens && !binding.x5t) {
    throw new OAuthError('invalid_request', {
      description: `client ${client.clientId} is registered for certificate-bound tokens and presented no client certificate`,
      spec: 'RFC 8705 §3'
    })
  }
  if (fapi && !binding.jkt && !binding.x5t) {
    throw new OAuthError('invalid_request', {
      description: `client ${client.clientId} is under FAPI 2.0, whose tokens are sender-constrained: present a DPoP proof or a client certificate`,
      spec: 'FAPI 2.0 Security Profile §5.3.2.1'
    })
  }

  const body = await (async () => {
    switch (grantType) {
      case 'authorization_code':
        return redeemAuthorizationCode(config, client, form, binding)
      case 'refresh_token':
        return redeemRefreshToken(config, client, form, binding)
      case 'client_credentials':
        return redeemClientCredentials(config, client, form, binding)
      case DEVICE_CODE_GRANT_TYPE:
        return redeemDeviceCode(config, client, form, binding)
      case TOKEN_EXCHANGE_GRANT_TYPE:
        return redeemSubjectToken(config, client, form, binding)
      case CIBA_GRANT_TYPE:
        return redeemCibaRequest(config, client, form, binding)
      case JWT_BEARER_GRANT_TYPE:
        return redeemIdentityAssertion(config, client, form, binding)
      default:
        throw new OAuthError('unsupported_grant_type', { description: `${grantType} is not supported`, spec: 'RFC 6749 §5.2' })
    }
  })()

  return Response.json(body, { headers: NO_STORE })
}
