import type { Features, ResolvedConfig, Ttl } from '../config'
import { OAuthError } from '../errors'
import type { ActiveKey } from '../keys/keys'
import type { Client, ClientAuthMethod } from '../types'

/** FAPI 2.0 Security Profile §5.4: what anything under the profile may sign with or be signed with. */
export const FAPI_ALGS = ['PS256', 'ES256', 'EdDSA']

/** §5.3.2.1: authentication by a key the client holds, never by a shared secret. */
export const FAPI_AUTH_METHODS: ClientAuthMethod[] = ['private_key_jwt', 'tls_client_auth', 'self_signed_tls_client_auth']

/** §5.3.2.1: a client assertion's `iat` may run this far ahead, and its `nbf` lag this far behind. */
export const FAPI_IAT_SKEW = 10
export const FAPI_NBF_MAX_AGE = 60

/** One switch, for the provider or for a client; never assembled from individual settings (FR-C21). */
export const underFapi = (config: Pick<ResolvedConfig, 'profile'>, client: Pick<Client, 'profile'> | undefined) =>
  config.profile === 'fapi2' || client?.profile === 'fapi2'

type ProviderShape = { features: Features; ttl: Ttl; clientAuthMethods: ClientAuthMethod[]; clientCertificate: boolean }

/** What a provider must be able to do before any client may be FAPI (FR-C21, NFR-D2). */
export const fapiProviderProblems = ({ features, ttl, clientAuthMethods, clientCertificate }: ProviderShape) => {
  const problems: string[] = []
  if (!features.pushedAuthorizationRequests) problems.push('FAPI 2.0 needs features.pushedAuthorizationRequests')
  if (!features.dpop && !clientCertificate) {
    problems.push('FAPI 2.0 needs sender-constrained tokens: features.dpop, or capabilities.clientCertificate for mTLS')
  }
  if (!clientAuthMethods.some(method => FAPI_AUTH_METHODS.includes(method))) {
    problems.push(`FAPI 2.0 needs one of ${FAPI_AUTH_METHODS.join(', ')} in clientAuthMethods`)
  }
  if (ttl.pushedAuthorizationRequest >= 600) problems.push('FAPI 2.0 needs ttl.pushedAuthorizationRequest under 600 seconds')
  if (ttl.authorizationCode > 60) problems.push('FAPI 2.0 needs ttl.authorizationCode of at most 60 seconds')
  return problems
}

/** What a client under the profile must be; empty when it is not under it. */
export const fapiClientProblems = (config: ResolvedConfig, client: Client) => {
  if (!underFapi(config, client)) return []
  const problems =
    config.profile === 'fapi2' ? [] : fapiProviderProblems({ ...config, clientCertificate: config.capabilities.clientCertificate })
  if (!FAPI_AUTH_METHODS.includes(client.tokenEndpointAuthMethod)) {
    problems.push(`authenticates with ${client.tokenEndpointAuthMethod}; FAPI 2.0 allows ${FAPI_AUTH_METHODS.join(', ')}`)
  }
  for (const uri of client.redirectUris) {
    if (uri.startsWith('http:') && client.applicationType !== 'native')
      problems.push(`redirect URI ${uri} is http and the client is not native`)
  }
  for (const [name, alg] of [
    ['idTokenSignedResponseAlg', client.idTokenSignedResponseAlg],
    ['userinfoSignedResponseAlg', client.userinfoSignedResponseAlg]
  ]) {
    if (alg && !FAPI_ALGS.includes(alg)) problems.push(`${name} ${alg} is not one of ${FAPI_ALGS.join(', ')}`)
  }
  return problems
}

/** At request time too: a client can reach storage without passing registration or the management API. */
export const assertFapiClient = (config: ResolvedConfig, client: Client) => {
  const problems = fapiClientProblems(config, client)
  if (problems.length) {
    throw new OAuthError('invalid_client', {
      description: `client ${client.clientId} does not meet FAPI 2.0: ${problems.join('; ')}`,
      spec: 'FAPI 2.0 Security Profile §5'
    })
  }
}

/** The algorithm a token for this client is signed with when it named none: the first key the profile allows. */
export const defaultSigningAlg = (config: ResolvedConfig, client: Client | undefined, keys: ActiveKey[]) =>
  underFapi(config, client) ? keys.find(key => FAPI_ALGS.includes(key.alg))?.alg : keys[0]?.alg
