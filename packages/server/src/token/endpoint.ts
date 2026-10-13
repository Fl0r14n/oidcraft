import { CIBA_GRANT, cibaGrant } from '../authorize/ciba'
import { deviceCodeGrant } from '../authorize/device'
import { verifyDpopProof } from '../binding/dpop'
import { authenticateClient } from '../clients/authenticate'
import { publicUrl, type ResolvedConfig } from '../config'
import type { ClientCertificate } from '../context'
import { OAuthError } from '../errors'
import type { Client } from '../types'
import { clientCredentialsGrant } from './client-credentials'
import { authorizationCodeGrant, refreshTokenGrant } from './code'
import { exchangeGrant, TOKEN_EXCHANGE } from './exchange'

const NO_STORE = { 'cache-control': 'no-store', pragma: 'no-cache' }

/** A client may always offer a proof; one registered for bound tokens must (RFC 9449 §5). */
const bindingFor = async (config: ResolvedConfig, client: Client, request: Request) => {
  if (!config.features.dpop) return undefined
  const offered = request.headers.has('dpop')
  if (!offered) {
    if (!client.dpopBoundAccessTokens) return undefined
    throw new OAuthError('invalid_dpop_proof', {
      description: `client ${client.clientId} is registered for DPoP-bound tokens and presented no proof`,
      spec: 'RFC 9449 §5'
    })
  }
  return (
    await verifyDpopProof(config, request, {
      htu: publicUrl(config, request),
      requireNonceFor: config.features.dpopNonces ? client.clientId : undefined
    })
  ).jkt
}

export const tokenEndpoint = async (config: ResolvedConfig, request: Request, certificate?: ClientCertificate | undefined) => {
  const form = new URLSearchParams(await request.text())
  const { client } = await authenticateClient(config, form, request.headers, certificate)

  const grantType = form.get('grant_type')
  if (!grantType) throw new OAuthError('invalid_request', { description: 'grant_type is required' })
  if (!client.grantTypes.includes(grantType)) {
    throw new OAuthError('unauthorized_client', { description: `client ${client.clientId} may not use grant_type ${grantType}` })
  }

  const jkt = await bindingFor(config, client, request)
  // RFC 8705 §3: binding to the certificate the client already presented costs nothing extra and
  // makes a stolen token useless without the private key behind it.
  const binding = { jkt, x5t: client.certificateBoundAccessTokens ? certificate?.thumbprint : undefined }

  const body = await (async () => {
    switch (grantType) {
      case 'authorization_code':
        return authorizationCodeGrant(config, client, form, binding)
      case 'refresh_token':
        return refreshTokenGrant(config, client, form, binding)
      case 'client_credentials':
        return clientCredentialsGrant(config, client, form, binding)
      case 'urn:ietf:params:oauth:grant-type:device_code':
        return deviceCodeGrant(config, client, form, binding)
      case TOKEN_EXCHANGE:
        return exchangeGrant(config, client, form, binding)
      case CIBA_GRANT:
        return cibaGrant(config, client, form, binding)
      default:
        throw new OAuthError('unsupported_grant_type', { description: `${grantType} is not supported` })
    }
  })()

  return Response.json(body, { headers: NO_STORE })
}
