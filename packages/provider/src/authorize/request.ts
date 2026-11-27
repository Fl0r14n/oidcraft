import type { Client } from '@oidcraft/adapter'
import { redirectMatches } from '../clients/uris'
import type { ResolvedConfig } from '../config'
import { OAuthError } from '../errors'
import { type ClaimsRequest, parseClaimsRequest } from './claims'
import { assertChallenge } from './pkce'
import { requestedResources } from './resources'
import { RESPONSE_MODES } from './response'

export type AuthorizationRequest = {
  clientId: string
  redirectUri: string
  responseType: string
  responseMode: string
  scopes: string[]
  state: string | undefined
  nonce: string | undefined
  codeChallenge: string | undefined
  prompt: string[]
  maxAge: number | undefined
  loginHint: string | undefined
  acrValues: string[] | undefined
  /** FR-C23: the client's `default_acr_values`, voluntary — shown to a login that happens, never a reason to ask for one. */
  defaultAcrValues: string[] | undefined
  uiLocales: string[] | undefined
  /** RFC 9396: what the client wants to do, not merely which scopes it holds. */
  authorizationDetails: AuthorizationDetail[] | undefined
  /** RFC 8707: the resources the token is for; each one configured, or the request is refused (FR-C19). */
  resources: string[]
  /** RFC 9449 §10: the DPoP key the code is for; only a proof made with it may redeem the code. */
  dpopJkt: string | undefined
  /** OIDC Core §5.5: claims asked for by name, and what the login must satisfy (FR-C22). */
  claims: ClaimsRequest | undefined
  /** The request as it arrived. Resuming replays this, never a rebuild from the fields above, which would drop what they omit. */
  raw: string
  /** Arrived by pushed reference, so it resumes by one: its parameters never cross the front channel (RFC 9126). */
  pushed?: true
}

/** RFC 9396 §2. `type` is the only member the spec fixes; the rest is the host's schema. */
export type AuthorizationDetail = { type: string } & Record<string, unknown>

const SUPPORTED_RESPONSE_TYPES = ['code']

const list = (value: string | null) => (value ? value.split(' ').filter(Boolean) : [])

// A bad `client_id` or unregistered `redirect_uri` must not redirect: open redirector (RFC 6749 §4.1.2.1, RFC 9700 §4.1).
export const parseAuthorizationRequest = async (config: ResolvedConfig, params: URLSearchParams) => {
  const clientId = params.get('client_id')
  if (!clientId) throw new OAuthError('invalid_request', { description: 'client_id is required', spec: 'RFC 6749 §4.1.1' })

  const client = await config.adapter.clients.find(clientId)
  if (!client) throw new OAuthError('invalid_request', { description: `unknown client ${clientId}`, spec: 'RFC 6749 §4.1.2.1' })

  const redirectUri = params.get('redirect_uri')
  if (!redirectUri) throw new OAuthError('invalid_request', { description: 'redirect_uri is required', spec: 'RFC 6749 §4.1.1' })

  const native = client.applicationType === 'native'
  if (!client.redirectUris.some(registered => redirectMatches(registered, redirectUri, native))) {
    throw new OAuthError('invalid_request', {
      description: `redirect_uri ${redirectUri} is not registered for ${clientId}`,
      spec: 'RFC 6749 §3.1.2.3, RFC 9700 §4.1.3'
    })
  }

  return { client, redirectUri }
}

// Past this point a failure is reported to the client by redirect.
export const validateAuthorizationRequest = (
  config: ResolvedConfig,
  client: Client,
  redirectUri: string,
  params: URLSearchParams
): AuthorizationRequest => {
  const responseType = params.get('response_type') ?? ''
  if (!SUPPORTED_RESPONSE_TYPES.includes(responseType)) {
    throw new OAuthError('unsupported_response_type', {
      description: `response_type ${responseType || 'none'} is not supported; this provider issues authorization codes`,
      spec: 'OAuth 2.1 §1.3'
    })
  }
  if (!client.responseTypes.includes(responseType)) {
    throw new OAuthError('unauthorized_client', {
      description: `client ${client.clientId} may not use response_type ${responseType}`,
      spec: 'RFC 6749 §4.1.2.1'
    })
  }

  const scopes = list(params.get('scope'))
  if (!scopes.includes('openid')) {
    throw new OAuthError('invalid_scope', { description: 'scope must include openid', spec: 'OIDC Core §3.1.2.1' })
  }
  const unknown = scopes.filter(scope => !config.scopes.includes(scope))
  if (unknown.length) throw new OAuthError('invalid_scope', { description: `unknown scope: ${unknown.join(', ')}`, spec: 'RFC 6749 §3.3' })
  const unallowed = scopes.filter(scope => !client.scopes.includes(scope))
  if (unallowed.length) {
    throw new OAuthError('invalid_scope', {
      description: `client ${client.clientId} may not request: ${unallowed.join(', ')}`,
      spec: 'RFC 6749 §3.3'
    })
  }

  const prompt = list(params.get('prompt'))
  if (prompt.includes('none') && prompt.length > 1) {
    throw new OAuthError('invalid_request', {
      description: 'prompt=none cannot be combined with another value',
      spec: 'OIDC Core §3.1.2.1'
    })
  }

  const maxAgeRaw = params.get('max_age')
  const maxAge = maxAgeRaw === null ? undefined : Number(maxAgeRaw)
  if (maxAge !== undefined && (!Number.isInteger(maxAge) || maxAge < 0)) {
    throw new OAuthError('invalid_request', {
      description: 'max_age must be a non-negative whole number of seconds',
      spec: 'OIDC Core §3.1.2.1'
    })
  }

  const claims = parseClaimsRequest(config, client, params.get('claims'))

  const responseMode = params.get('response_mode') ?? 'query'
  if (!RESPONSE_MODES.includes(responseMode)) {
    throw new OAuthError('invalid_request', { description: `unsupported response_mode ${responseMode}`, spec: 'OIDC Core §3.1.2.1' })
  }

  return {
    clientId: client.clientId,
    redirectUri,
    responseType,
    responseMode,
    scopes,
    state: params.get('state') ?? undefined,
    nonce: params.get('nonce') ?? undefined,
    codeChallenge: assertChallenge(client, params.get('code_challenge'), params.get('code_challenge_method'), params.get('nonce')),
    prompt,
    maxAge,
    loginHint: params.get('login_hint') ?? undefined,
    acrValues: params.get('acr_values') ? list(params.get('acr_values')) : undefined,
    defaultAcrValues: params.has('acr_values') || claims?.acrNamed ? undefined : client.defaultAcrValues,
    uiLocales: params.get('ui_locales') ? list(params.get('ui_locales')) : undefined,
    authorizationDetails: parseAuthorizationDetails(config, params.get('authorization_details')),
    resources: requestedResources(config, params, client.clientId),
    dpopJkt: config.features.dpop ? dpopJktFrom(params.get('dpop_jkt')) : undefined,
    claims,
    raw: params.toString()
  }
}

// An RFC 7638 SHA-256 thumbprint: 32 bytes, base64url without padding.
const JKT = /^[A-Za-z0-9_-]{43}$/

const dpopJktFrom = (value: string | null) => {
  if (value === null) return undefined
  if (!JKT.test(value)) {
    throw new OAuthError('invalid_request', { description: 'dpop_jkt is not a SHA-256 JWK thumbprint', spec: 'RFC 9449 §10' })
  }
  return value
}

const parseAuthorizationDetails = (config: ResolvedConfig, raw: string | null) => {
  if (!raw) return undefined
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    throw new OAuthError('invalid_authorization_details', { description: 'authorization_details is not JSON', spec: 'RFC 9396 §5' })
  }
  if (!Array.isArray(parsed) || parsed.length === 0) {
    throw new OAuthError('invalid_authorization_details', {
      description: 'authorization_details must be a non-empty array',
      spec: 'RFC 9396 §2'
    })
  }
  for (const detail of parsed) {
    const type = typeof detail === 'object' && detail !== null ? (detail as { type?: unknown }).type : undefined
    if (typeof type !== 'string') {
      throw new OAuthError('invalid_authorization_details', {
        description: 'every authorization detail needs a string type',
        spec: 'RFC 9396 §2'
      })
    }
    // Only the host knows what its types mean, so an undeclared one is refused rather than silently granted.
    if (!config.authorizationDetailTypes.includes(type)) {
      throw new OAuthError('invalid_authorization_details', {
        description: `authorization_details type ${type} is not supported`,
        spec: 'RFC 9396 §5'
      })
    }
  }
  return parsed as AuthorizationDetail[]
}
