import type { Client, ClientAuthMethod } from '@oidcraft/adapter'
import { constantTimeEquals, randomString } from '@oidcraft/core'
import { storedId } from '../artifacts'
import { audit } from '../audit'
import { CIBA_GRANT } from '../authorize/ciba'
import type { ResolvedConfig } from '../config'
import { supportedGrantTypes } from '../discovery'
import { OAuthError } from '../errors'
import { guarded } from '../hooks'
import { signingAlgorithms } from '../keys/keys'
import { defaultSigningAlg } from '../profile/fapi'
import { deleteClient } from './delete'
import { secretKind, storableSecret } from './secret'
import { clientProblems } from './validate'

const DEFAULT_GRANTS = ['authorization_code']

/** Registration refuses with RFC 7591's codes; a metadata document, read at the authorization endpoint, does not. */
export type Refuse = (description: string) => OAuthError

const invalid: Refuse = description => new OAuthError('invalid_client_metadata', { description, spec: 'RFC 7591 §3.2.2', status: 400 })
const invalidRedirect: Refuse = description => new OAuthError('invalid_redirect_uri', { description, spec: 'RFC 7591 §3.2.2', status: 400 })

// RFC 8252 §8.3: loopback means the IP literal. `localhost` can be resolved elsewhere.
const isLoopbackIp = (url: URL) => url.hostname === '127.0.0.1' || url.hostname === '[::1]'

// Each would run script, or read a file, wherever the browser is sent or a form is posted.
const FORBIDDEN_SCHEMES = ['javascript:', 'data:', 'vbscript:', 'file:']

export const browserUri = (raw: unknown, name: string, { native = false, fail = invalid }: { native?: boolean; fail?: Refuse } = {}) => {
  if (typeof raw !== 'string' || !URL.canParse(raw)) throw fail(`${name} ${String(raw)} is not an absolute URL`)
  const url = new URL(raw)
  // A fragment can never be matched: the browser never sends it (RFC 6749 §3.1.2).
  if (url.hash) throw fail(`${name} ${raw} must not carry a fragment`)
  if (FORBIDDEN_SCHEMES.includes(url.protocol)) throw fail(`${name} ${raw} uses a scheme that can run script`)
  // A native app listens on this machine, and many say localhost: matched exactly, never by port (NFR-S2).
  const local = isLoopbackIp(url) || (native && url.hostname === 'localhost')
  if (url.protocol === 'http:' && !local) {
    throw fail(`${name} ${raw} must be https outside a loopback IP${native ? ' or localhost' : ''}`)
  }
  return raw
}

const isIpLiteral = (hostname: string) => hostname.startsWith('[') || /^\d+\.\d+\.\d+\.\d+$/.test(hostname)

// SSRF: an address literal or `localhost` is refused here; a name resolving inside the network is the host's to refuse (FR-A1).
export const serverUri = (raw: unknown, name: string, fail: Refuse = invalid) => {
  if (typeof raw !== 'string' || !URL.canParse(raw)) throw fail(`${name} ${String(raw)} is not an absolute URL`)
  const url = new URL(raw)
  if (url.protocol !== 'https:') throw fail(`${name} ${raw} must be https`)
  if (url.hash) throw fail(`${name} ${raw} must not carry a fragment`)
  if (isIpLiteral(url.hostname) || url.hostname === 'localhost' || url.hostname.endsWith('.localhost')) {
    throw fail(`${name} ${raw} must name a public host, not an address or localhost`)
  }
  return raw
}

const uriList = (value: unknown, name: string) => {
  if (!Array.isArray(value)) throw invalid(`${name} must be an array`)
  return value.map(each => browserUri(each, name))
}

// The one endpoint that lets a stranger write to the client store, so its metadata is checked as strictly as an operator's (NFR-S2).
const validateRedirectUris = (uris: unknown, native: boolean) => {
  if (!Array.isArray(uris) || uris.length === 0) throw invalidRedirect('redirect_uris is required and must be a non-empty array')
  return uris.map(each => browserUri(each, 'redirect_uri', { native, fail: invalidRedirect }))
}

/** OIDC DCR 1.0 §2: `web` when omitted. MCP clients must send it (MCP 2026-07-28). */
const applicationTypeFrom = (raw: unknown) => {
  if (raw === undefined || raw === 'web' || raw === 'native') return raw ?? 'web'
  throw invalid(`application_type ${String(raw)} is neither web nor native`)
}

/** FR-T1: `none` never, and never an algorithm the provider holds no key for. */
const assertSignable = async (config: ResolvedConfig, client: Client) => {
  const alg = client.idTokenSignedResponseAlg
  if (!alg) return
  if (!signingAlgorithms(await config.adapter.keys.active()).includes(alg)) {
    throw invalid(`id_token_signed_response_alg ${alg} is not one this provider signs with`)
  }
}

/** OIDC DCR 1.0 §5: every registered redirect_uri must be listed, or registration fails (FR-C18). */
const assertSector = async (config: ResolvedConfig, client: Client) => {
  const uri = client.sectorIdentifierUri
  if (uri === undefined) return
  if (!URL.canParse(uri) || new URL(uri).protocol !== 'https:') throw invalid('sector_identifier_uri must be an https URL')
  if (!config.resolveSectorIdentifier) throw invalid('this provider cannot validate a sector_identifier_uri')
  const listed = await config.resolveSectorIdentifier(uri).catch(() => {
    throw invalid(`sector_identifier_uri ${uri} could not be retrieved`)
  })
  if (!Array.isArray(listed)) throw invalid('sector_identifier_uri must reference a JSON array of redirect URIs')
  const missing = client.redirectUris.filter(each => !listed.includes(each))
  if (missing.length) throw invalid(`sector_identifier_uri does not list ${missing.join(', ')}`)
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
const grantsFrom = (config: ResolvedConfig, body: Record<string, unknown>, method: ClientAuthMethod) => {
  const grantTypes = stringsFrom(body.grant_types, 'grant_types') ?? DEFAULT_GRANTS
  if (!grantTypes.length) throw invalid('grant_types must not be empty')
  const offered = supportedGrantTypes(config)
  const unknown = grantTypes.filter(grant => !offered.includes(grant))
  if (unknown.length) throw invalid(`grant_types ${unknown.join(', ')} not offered by this provider`)
  if (method === 'none' && grantTypes.includes('client_credentials')) {
    throw invalid('a public client cannot use client_credentials (RFC 6749 §4.4)')
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
  const ciba = grantTypes.includes(CIBA_GRANT)
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

const assertRegistrable = async (config: ResolvedConfig, client: Client) => {
  await assertSignable(config, client)
  await assertSector(config, client)
  const problems = clientProblems(config, client)
  if (problems.length) throw invalid(problems.join('; '))
}

/** RFC 8705 §2.1.2's five registrations, as metadata names to `Client` fields. */
const TLS_CLIENT_AUTH_METADATA = {
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

const metadataFrom = (config: ResolvedConfig, body: Record<string, unknown>): Client => {
  const applicationType = applicationTypeFrom(body.application_type)
  const redirectUris = validateRedirectUris(body.redirect_uris, applicationType === 'native')
  const method = (stringFrom(body.token_endpoint_auth_method, 'token_endpoint_auth_method') ?? 'client_secret_basic') as ClientAuthMethod
  if (!config.clientAuthMethods.includes(method)) throw invalid(`token_endpoint_auth_method ${method} is not offered by this provider`)

  const { grantTypes, responseTypes } = grantsFrom(config, body, method)

  const scopes = (stringFrom(body.scope, 'scope') ?? 'openid').split(' ').filter(Boolean)
  const clientName = stringFrom(body.client_name, 'client_name')
  const sectorIdentifierUri = stringFrom(body.sector_identifier_uri, 'sector_identifier_uri')
  const unknown = scopes.filter(scope => !config.scopes.includes(scope))
  if (unknown.length) throw invalid(`unknown scope: ${unknown.join(', ')}`)

  const now = new Date()
  return {
    clientId: randomString(),
    ...(clientName !== undefined && { clientName }),
    applicationType,
    redirectUris,
    ...(body.post_logout_redirect_uris !== undefined && {
      postLogoutRedirectUris: uriList(body.post_logout_redirect_uris, 'post_logout_redirect_uri')
    }),
    grantTypes,
    responseTypes,
    scopes,
    tokenEndpointAuthMethod: method,
    ...(sectorIdentifierUri !== undefined && { sectorIdentifierUri }),
    ...subjectTypeFrom(config, body.subject_type),
    ...cibaMetadataFrom(body, grantTypes),
    // OIDC DCR 1.0 §2: RS256 when omitted, except under FAPI 2.0, which forbids it: the profile's default then (FR-T1, FR-C21).
    ...idTokenAlgFrom(config, body.id_token_signed_response_alg),
    ...(body.default_acr_values !== undefined && { defaultAcrValues: stringsFrom(body.default_acr_values, 'default_acr_values') ?? [] }),
    ...keysFrom(body),
    ...tlsClientAuthFrom(body),
    ...(body.backchannel_logout_uri !== undefined && {
      backchannelLogoutUri: serverUri(body.backchannel_logout_uri, 'backchannel_logout_uri')
    }),
    // FR-C3: registering itself gives no assurance; only the host's onRegister can exempt it.
    requirePkce: true,
    createdAt: now,
    updatedAt: now
  }
}

// What an update replaces or, left out, removes (RFC 7592 §2.2); the rest of a stored client is the operator's (FR-C9, FR-C21).
const REGISTERED = new Set<string>([
  ...['clientName', 'applicationType', 'redirectUris', 'postLogoutRedirectUris', 'grantTypes', 'responseTypes', 'scopes'],
  ...['tokenEndpointAuthMethod', 'clientSecret', 'clientSecretHash', 'sectorIdentifierUri', 'subjectType', 'requirePkce'],
  ...['backchannelTokenDeliveryMode', 'backchannelClientNotificationEndpoint', 'idTokenSignedResponseAlg', 'jwks', 'jwksUri'],
  ...['defaultAcrValues'],
  ...['backchannelLogoutUri', ...Object.values(TLS_CLIENT_AUTH_METADATA)]
])

const operatorFields = (client: Client) => Object.fromEntries(Object.entries(client).filter(([name]) => !REGISTERED.has(name)))

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
    client_id_issued_at: Math.floor(client.createdAt.getTime() / 1000),
    ...(registrationAccessToken && {
      registration_access_token: registrationAccessToken,
      registration_client_uri: `${config.issuer}${config.routes.registration}?client_id=${encodeURIComponent(client.clientId)}`
    })
  }
}

const authorizeRegistrationAccess = async (config: ResolvedConfig, request: Request, clientId: string | null) => {
  if (!clientId) throw new OAuthError('invalid_request', { description: 'client_id is required', status: 400, spec: 'RFC 7592 §2' })
  const header = request.headers.get('authorization')
  const presented = header?.toLowerCase().startsWith('bearer ') ? header.slice(7).trim() : undefined
  const client = await config.adapter.clients.find(clientId)
  // An unknown client and a wrong token are the same answer: otherwise this enumerates client ids.
  const matches = Boolean(
    client?.registrationAccessToken && presented && (await constantTimeEquals(await storedId(presented), client.registrationAccessToken))
  )
  if (!client || !presented || !matches) {
    throw new OAuthError('invalid_client', {
      description: 'no registration access token for this client',
      spec: 'RFC 7592 §2',
      status: 401,
      headers: { 'www-authenticate': 'Bearer' }
    })
  }
  return { client, presented }
}

/** FR-C3: only the host's onRegister can exempt a dynamically registered client, and never a public one. */
const applyDecision = (client: Client, decision: { requirePkce?: boolean } | undefined) => {
  if (decision?.requirePkce !== false) return
  if (client.tokenEndpointAuthMethod === 'none') throw invalid('a public client cannot be exempted from PKCE')
  client.requirePkce = false
}

/** OIDC Dynamic Client Registration 1.0 and RFC 7592. Off unless a deployment turns it on (FR-C9). */
const idTokenAlgFrom = (config: ResolvedConfig, value: unknown) => {
  const named = stringFrom(value, 'id_token_signed_response_alg')
  if (named !== undefined) return { idTokenSignedResponseAlg: named }
  return config.profile === 'fapi2' ? {} : { idTokenSignedResponseAlg: 'RS256' }
}

/** Under FAPI 2.0 the response names the algorithm it will sign with: to a DCR client an omitted one means RS256. */
const settleIdTokenAlg = async (config: ResolvedConfig, client: Client) => {
  if (client.idTokenSignedResponseAlg) return
  const alg = defaultSigningAlg(config, client, await config.adapter.keys.active())
  if (alg) client.idTokenSignedResponseAlg = alg
}

export const registrationEndpoint = async (config: ResolvedConfig, request: Request) => {
  const url = new URL(request.url)

  if (request.method === 'POST') {
    const decision = config.onRegister ? await config.onRegister(request.clone(), { existing: undefined }) : undefined
    const body = objectFrom(
      await request.json().catch(() => {
        throw invalid('the registration request must be JSON')
      }),
      'the registration request'
    )

    const { client, issued } = await storableSecret(metadataFrom(config, body), true)
    await settleIdTokenAlg(config, client)
    await assertRegistrable(config, client)
    applyDecision(client, decision)
    if (!config.adapter.clients.upsert) throw new OAuthError('server_error', { description: 'this adapter cannot create clients' })
    const registrationAccessToken = randomString()
    await config.adapter.clients.upsert({ ...client, registrationAccessToken: await storedId(registrationAccessToken) })
    await guarded(config, request, () => audit(config, 'client.register', { clientId: client.clientId }))
    return Response.json(clientResponse(config, client, registrationAccessToken, issued), {
      status: 201,
      headers: { 'cache-control': 'no-store' }
    })
  }

  const { client, presented } = await authorizeRegistrationAccess(config, request, url.searchParams.get('client_id'))

  if (request.method === 'GET') {
    return Response.json(clientResponse(config, client, presented), { headers: { 'cache-control': 'no-store' } })
  }

  if (request.method === 'DELETE') {
    await deleteClient(config, client.clientId)
    await guarded(config, request, () => audit(config, 'client.delete', { clientId: client.clientId }))
    return new Response(null, { status: 204, headers: { 'cache-control': 'no-store' } })
  }

  // The host vets an update as it vetted the first registration; its answer, not the stored client, decides PKCE (FR-C3).
  const decision = config.onRegister ? await config.onRegister(request.clone(), { existing: client }) : undefined
  const body = objectFrom(
    await request.json().catch(() => {
      throw invalid('the update must be JSON')
    }),
    'the update'
  )
  const metadata = metadataFrom(config, body)
  // A secret survives a method change only where it is kept the same way; otherwise a new one is issued.
  const sameSecret = secretKind(metadata.tokenEndpointAuthMethod) === secretKind(client.tokenEndpointAuthMethod)
  // Identity and the token that grants access to it are the server's, not the client's to change.
  const { client: updated, issued } = await storableSecret(
    {
      ...operatorFields(client),
      ...metadata,
      clientId: client.clientId,
      ...(sameSecret && client.clientSecret && { clientSecret: client.clientSecret }),
      ...(sameSecret && client.clientSecretHash && { clientSecretHash: client.clientSecretHash }),
      registrationAccessToken: client.registrationAccessToken as string,
      createdAt: client.createdAt,
      updatedAt: new Date()
    },
    true
  )
  await settleIdTokenAlg(config, updated)
  await assertRegistrable(config, updated)
  applyDecision(updated, decision)
  if (!config.adapter.clients.upsert) throw new OAuthError('server_error', { description: 'this adapter cannot update clients' })
  await config.adapter.clients.upsert(updated)
  await guarded(config, request, () => audit(config, 'client.update', { clientId: client.clientId }))
  return Response.json(clientResponse(config, updated, presented, issued), { headers: { 'cache-control': 'no-store' } })
}
