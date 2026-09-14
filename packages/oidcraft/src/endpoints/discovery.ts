import type { ResolvedConfig } from '../config'
import { signingAlgorithms } from '../keys'
import type { ClientAuthMethod } from '../types'

const MTLS_METHODS: ClientAuthMethod[] = ['tls_client_auth', 'self_signed_tls_client_auth']

/**
 * Advertises only what this configuration can actually do (FR-C6). A capability the runtime cannot
 * supply removes the methods that need it rather than listing them (FR-R5).
 */
export const metadata = (config: ResolvedConfig, algorithms: string[]) => {
  const url = (path: string) => `${config.issuer}${path}`
  const { features, routes } = config

  const authMethods = config.clientAuthMethods.filter(method => config.capabilities.clientCertificate || !MTLS_METHODS.includes(method))

  const grantTypes = ['authorization_code', 'refresh_token', 'client_credentials']
  if (features.deviceFlow) grantTypes.push('urn:ietf:params:oauth:grant-type:device_code')

  return {
    issuer: config.issuer,
    authorization_endpoint: url(routes.authorization),
    token_endpoint: url(routes.token),
    userinfo_endpoint: url(routes.userinfo),
    jwks_uri: url(routes.jwks),
    end_session_endpoint: url(routes.endSession),
    ...(features.revocation && { revocation_endpoint: url(routes.revocation) }),
    ...(features.introspection && { introspection_endpoint: url(routes.introspection) }),
    ...(features.dynamicRegistration && { registration_endpoint: url(routes.registration) }),
    ...(features.deviceFlow && { device_authorization_endpoint: url(routes.deviceAuthorization) }),
    ...(features.pushedAuthorizationRequests && {
      pushed_authorization_request_endpoint: url(routes.pushedAuthorizationRequest),
      require_pushed_authorization_requests: false
    }),
    scopes_supported: config.scopes,
    // FR-C1: no implicit, no hybrid-with-token — OAuth 2.1 removes them and RFC 9700 §2.1.2 forbids them.
    response_types_supported: ['code', 'id_token', 'code id_token'],
    response_modes_supported: ['query', 'fragment', 'form_post'],
    grant_types_supported: grantTypes,
    subject_types_supported: config.pairwiseSalt ? ['public', 'pairwise'] : ['public'],
    id_token_signing_alg_values_supported: algorithms,
    token_endpoint_auth_methods_supported: authMethods,
    token_endpoint_auth_signing_alg_values_supported: algorithms,
    claims_supported: ['sub', 'iss', 'aud', 'exp', 'iat', 'auth_time', 'nonce', 'acr', 'amr', 'azp', ...claimsFrom(config)],
    claim_types_supported: ['normal'],
    // FR-C3: mandatory for every client, and never `plain`.
    code_challenge_methods_supported: ['S256'],
    // FR-C14: unconditional.
    authorization_response_iss_parameter_supported: true,
    ...(features.dpop && { dpop_signing_alg_values_supported: algorithms }),
    // JAR by value only: resolving a client-supplied request_uri would be outbound I/O (FR-A1).
    request_parameter_supported: true,
    request_uri_parameter_supported: false,
    require_request_uri_registration: false,
    request_object_signing_alg_values_supported: ['ES256', 'ES384', 'ES512', 'PS256', 'RS256'],
    claims_parameter_supported: false,
    frontchannel_logout_supported: true,
    backchannel_logout_supported: true
  }
}

const claimsFrom = (config: ResolvedConfig) => [...new Set(Object.values(config.claims).flat())]

export const discoveryEndpoint = async (config: ResolvedConfig) => {
  const keys = await config.adapter.keys.active()
  return Response.json(metadata(config, signingAlgorithms(keys)), {
    headers: { 'cache-control': 'public, max-age=300' }
  })
}
