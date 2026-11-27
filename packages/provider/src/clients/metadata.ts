import type { Client, ClientAuthMethod } from '@oidcraft/adapter'
import { randomString } from '@oidcraft/core'
import { CIBA_GRANT_TYPE } from '../authorize/ciba'
import type { ResolvedConfig } from '../config'
import { supportedGrantTypes } from '../discovery'
import { OAuthError } from '../errors'
import { underFapi } from '../profile/fapi'
import { JWT_BEARER_GRANT_TYPE } from '../token/identity-assertion'
import { browserUri, invalidMetadata, isNativeRedirect, type Refuse, serverUri } from './uris'

const DEFAULT_GRANT_TYPES = ['authorization_code']

export const invalid = invalidMetadata
const invalidRedirect: Refuse = description => new OAuthError('invalid_redirect_uri', { description, spec: 'RFC 7591 §3.2.2', status: 400 })

const uriList = (value: unknown, name: string, native: boolean) => {
  if (!Array.isArray(value)) throw invalid(`${name} must be an array`)
  return value.map(each => browserUri(each, name, { native }))
}

// The one endpoint that lets a stranger write to the client store, so its metadata is checked as strictly as an operator's (NFR-S2).
const assertRedirectUris = (uris: unknown, native: boolean) => {
  if (!Array.isArray(uris) || uris.length === 0) throw invalidRedirect('redirect_uris is required and must be a non-empty array')
  return uris.map(each => browserUri(each, 'redirect_uri', { native, fail: invalidRedirect }))
}

/**
 * OIDC DCR 1.0 §2: `web` when omitted — save a client whose every redirect is a loopback IP or an app's own scheme, which
 * only a native app can receive. MCP 2026-07-28 clients send it; earlier ones register such redirects without it.
 */
const applicationTypeFrom = (raw: unknown, redirectUris: unknown) => {
  if (raw === 'web' || raw === 'native') return raw
  if (raw !== undefined) throw invalid(`application_type ${String(raw)} is neither web nor native`)
  const native = Array.isArray(redirectUris) && redirectUris.length > 0 && redirectUris.every(isNativeRedirect)
  return native ? 'native' : 'web'
}

const isObject = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value)

/** FR-C9: the metadata is a stranger's JSON, so its shape is checked rather than cast. */
export const objectFrom = (value: unknown, what: string, fail: Refuse = invalid) => {
  if (!isObject(value)) throw fail(`${what} must be a JSON object`)
  return value
}

export const stringFrom = (value: unknown, name: string, fail: Refuse = invalid) => {
  if (value === undefined) return undefined
  if (typeof value !== 'string') throw fail(`${name} must be a string`)
  return value
}

export const stringsFrom = (value: unknown, name: string, fail: Refuse = invalid) => {
  if (value === undefined) return undefined
  if (!Array.isArray(value) || !value.every(each => typeof each === 'string')) throw fail(`${name} must be an array of strings`)
  return value as string[]
}

// RFC 7518 §6: what makes an RSA, EC or OKP key private, and `k`, which is a symmetric key whole.
const PRIVATE_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k']

/** RFC 7591 §2: a client registers public keys, by value or by reference, never both. */
export const keysFrom = (body: Record<string, unknown>, fail: Refuse = invalid) => {
  if (body.jwks !== undefined && body.jwks_uri !== undefined) throw fail('jwks and jwks_uri must not both be given')
  if (body.jwks_uri !== undefined) return { jwksUri: serverUri(body.jwks_uri, 'jwks_uri', fail) }
  if (body.jwks === undefined) return {}
  const keys = isObject(body.jwks) ? body.jwks.keys : undefined
  if (!Array.isArray(keys) || !keys.every(key => isObject(key) && typeof key.kty === 'string')) {
    throw fail('jwks must be a JWK Set: an object whose keys is an array of keys')
  }
  if (keys.some(key => PRIVATE_MEMBERS.some(member => member in key))) throw fail('jwks must hold public keys only')
  return { jwks: { keys: keys as unknown[] } }
}

/** The client store's `grantTypes` is what the token endpoint enforces, so a stranger must not choose it freely (FR-C9). */
const grantTypesFrom = (config: ResolvedConfig, body: Record<string, unknown>, method: ClientAuthMethod) => {
  const grantTypes = stringsFrom(body.grant_types, 'grant_types') ?? DEFAULT_GRANT_TYPES
  if (!grantTypes.length) throw invalid('grant_types must not be empty')
  const offered = supportedGrantTypes(config)
  const unknown = grantTypes.filter(grant => !offered.includes(grant))
  if (unknown.length) throw invalid(`grant_types ${unknown.join(', ')} not offered by this provider`)
  if (method === 'none' && grantTypes.includes('client_credentials')) {
    throw invalid('a public client cannot use client_credentials (RFC 6749 §4.4)')
  }
  if (method === 'none' && grantTypes.includes(JWT_BEARER_GRANT_TYPE)) {
    throw invalid('a public client cannot redeem an identity assertion (FR-C24.3)')
  }

  const code = grantTypes.includes('authorization_code')
  const responseTypes = stringsFrom(body.response_types, 'response_types') ?? (code ? ['code'] : [])
  if (responseTypes.some(type => type.split(' ').includes('token')))
    throw invalid('this provider issues no tokens from the authorization endpoint')
  const unsupported = responseTypes.filter(type => type !== 'code')
  if (unsupported.length) throw invalid(`response_types ${unsupported.join(', ')} not offered by this provider`)
  // OIDC DCR 1.0 §2: the two lists must agree, or the client is registered for a flow it cannot finish.
  if (code !== responseTypes.includes('code')) throw invalid('response_types code and grant_types authorization_code go together')
  return { grantTypes, responseTypes }
}

// OIDC CIBA 1.0 §4; push mode is out of scope (FR-C17).
const cibaMetadataFrom = (body: Record<string, unknown>, grantTypes: string[]) => {
  const mode = body.backchannel_token_delivery_mode
  const ciba = grantTypes.includes(CIBA_GRANT_TYPE)
  if (mode === undefined) {
    if (ciba) throw invalid('a client of the CIBA grant must declare backchannel_token_delivery_mode')
    return {}
  }
  if (!ciba) throw invalid('backchannel_token_delivery_mode needs the CIBA grant type')
  if (mode !== 'poll' && mode !== 'ping') throw invalid(`backchannel_token_delivery_mode ${String(mode)} is not supported; poll or ping`)
  if (mode === 'poll') return { backchannelTokenDeliveryMode: mode } as const
  // The host posts to it on a stranger's say-so, so it is held to the same rule as the other server-side URIs.
  return {
    backchannelTokenDeliveryMode: mode,
    backchannelClientNotificationEndpoint: serverUri(
      body.backchannel_client_notification_endpoint,
      'backchannel_client_notification_endpoint'
    )
  } as const
}

const subjectTypeFrom = (config: ResolvedConfig, requested: unknown) => {
  if (requested === undefined) return {}
  if (requested !== 'public' && requested !== 'pairwise') throw invalid(`subject_type ${String(requested)} is not supported`)
  if (requested === 'pairwise' && !config.pairwiseSalt) throw invalid('this provider does not issue pairwise subjects')
  return { subjectType: requested } as const
}

/** RFC 8705 §2.1.2's five registrations, as metadata names to `Client` fields. */
export const TLS_CLIENT_AUTH_METADATA = {
  tls_client_auth_subject_dn: 'tlsClientAuthSubjectDn',
  tls_client_auth_san_dns: 'tlsClientAuthSanDns',
  tls_client_auth_san_uri: 'tlsClientAuthSanUri',
  tls_client_auth_san_ip: 'tlsClientAuthSanIp',
  tls_client_auth_san_email: 'tlsClientAuthSanEmail'
} as const

const tlsClientAuthFrom = (body: Record<string, unknown>) => {
  const fields: Partial<Pick<Client, (typeof TLS_CLIENT_AUTH_METADATA)[keyof typeof TLS_CLIENT_AUTH_METADATA]>> = {}
  for (const [name, field] of Object.entries(TLS_CLIENT_AUTH_METADATA)) {
    const value = stringFrom(body[name], name)
    if (value !== undefined) fields[field] = value
  }
  return fields
}

const idTokenAlgFrom = (config: ResolvedConfig, value: unknown, existing: Client | undefined) => {
  const named = stringFrom(value, 'id_token_signed_response_alg')
  if (named !== undefined) return { idTokenSignedResponseAlg: named }
  return underFapi(config, existing) ? {} : { idTokenSignedResponseAlg: 'RS256' }
}

export const metadataFrom = (config: ResolvedConfig, body: Record<string, unknown>, existing?: Client): Client => {
  const applicationType = applicationTypeFrom(body.application_type, body.redirect_uris)
  const redirectUris = assertRedirectUris(body.redirect_uris, applicationType === 'native')
  const method = (stringFrom(body.token_endpoint_auth_method, 'token_endpoint_auth_method') ?? 'client_secret_basic') as ClientAuthMethod
  if (!config.clientAuthMethods.includes(method)) throw invalid(`token_endpoint_auth_method ${method} is not offered by this provider`)

  const { grantTypes, responseTypes } = grantTypesFrom(config, body, method)

  const scopes = (stringFrom(body.scope, 'scope') ?? 'openid').split(' ').filter(Boolean)
  const clientName = stringFrom(body.client_name, 'client_name')
  const sectorIdentifierUri = stringFrom(body.sector_identifier_uri, 'sector_identifier_uri')
  const unknown = scopes.filter(scope => !config.scopes.includes(scope))
  if (unknown.length) throw invalid(`unknown scope: ${unknown.join(', ')}`)

  const now = Date.now()
  return {
    clientId: randomString(),
    ...(clientName !== undefined && { clientName }),
    applicationType,
    redirectUris,
    ...(body.post_logout_redirect_uris !== undefined && {
      postLogoutRedirectUris: uriList(body.post_logout_redirect_uris, 'post_logout_redirect_uri', applicationType === 'native')
    }),
    grantTypes,
    responseTypes,
    scopes,
    tokenEndpointAuthMethod: method,
    ...(sectorIdentifierUri !== undefined && { sectorIdentifierUri }),
    ...subjectTypeFrom(config, body.subject_type),
    ...cibaMetadataFrom(body, grantTypes),
    // OIDC DCR 1.0 §2: RS256 when omitted, except under FAPI 2.0, which forbids it: the profile's default then (FR-T1, FR-C21).
    ...idTokenAlgFrom(config, body.id_token_signed_response_alg, existing),
    ...(body.default_acr_values !== undefined && { defaultAcrValues: stringsFrom(body.default_acr_values, 'default_acr_values') ?? [] }),
    ...keysFrom(body),
    ...tlsClientAuthFrom(body),
    ...(body.backchannel_logout_uri !== undefined && {
      backchannelLogoutUri: serverUri(body.backchannel_logout_uri, 'backchannel_logout_uri')
    }),
    // FR-C3: registering itself gives no assurance; only the host's registrationPolicy can exempt it.
    requirePkce: true,
    createdAt: now,
    updatedAt: now
  }
}

// Secrets are stored as digests, so a response carries one only when the caller holds it or it was just issued (NFR-S11).
export const clientResponse = (
  config: ResolvedConfig,
  client: Omit<Client, 'clientSecretHash' | 'registrationAccessToken'>,
  registrationAccessToken?: string,
  issuedSecret?: string
) => {
  const secret = issuedSecret ?? client.clientSecret
  return {
    client_id: client.clientId,
    ...(secret && { client_secret: secret, client_secret_expires_at: 0 }),
    ...(client.clientName && { client_name: client.clientName }),
    redirect_uris: client.redirectUris,
    application_type: client.applicationType ?? 'web',
    grant_types: client.grantTypes,
    response_types: client.responseTypes,
    scope: client.scopes.join(' '),
    token_endpoint_auth_method: client.tokenEndpointAuthMethod,
    ...(client.sectorIdentifierUri && { sector_identifier_uri: client.sectorIdentifierUri }),
    ...(client.subjectType && { subject_type: client.subjectType }),
    ...(client.backchannelTokenDeliveryMode && { backchannel_token_delivery_mode: client.backchannelTokenDeliveryMode }),
    ...(client.backchannelClientNotificationEndpoint && {
      backchannel_client_notification_endpoint: client.backchannelClientNotificationEndpoint
    }),
    ...(client.idTokenSignedResponseAlg && { id_token_signed_response_alg: client.idTokenSignedResponseAlg }),
    ...(client.defaultAcrValues && { default_acr_values: client.defaultAcrValues }),
    ...Object.fromEntries(
      Object.entries(TLS_CLIENT_AUTH_METADATA)
        .filter(([, field]) => client[field] !== undefined)
        .map(([name, field]) => [name, client[field]])
    ),
    client_id_issued_at: Math.floor(client.createdAt / 1000),
    ...(registrationAccessToken && {
      registration_access_token: registrationAccessToken,
      registration_client_uri: `${config.issuer}${config.routes.registration}?client_id=${encodeURIComponent(client.clientId)}`
    })
  }
}
