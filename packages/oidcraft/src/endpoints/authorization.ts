import type { ResolvedConfig } from '../config'
import { OAuthError } from '../errors'
import { assertChallenge } from '../pkce'
import { token } from '../random'
import { isFresh } from '../session'
import type { Artifact, Client, Grant, Session } from '../types'
import { selectUpstream } from '../upstreams'

export type AuthorizationRequest = {
  clientId: string
  redirectUri: string
  responseType: string
  responseMode: string
  scopes: string[]
  state: string | undefined
  nonce: string | undefined
  codeChallenge: string
  prompt: string[]
  maxAge: number | undefined
  loginHint: string | undefined
  acrValues: string[] | undefined
  uiLocales: string[] | undefined
  /** RFC 9396: what the client wants to do, not merely which scopes it holds. */
  authorizationDetails: AuthorizationDetail[] | undefined
  /**
   * The request exactly as it arrived. Resuming after an interaction replays this rather than
   * rebuilding from the fields above: a hand-maintained list silently drops every parameter nobody
   * remembered to add to it, which is how `authorization_details` went missing once already.
   */
  raw: string
}

/** RFC 9396 §2. `type` is the only member the spec fixes; the rest is the host's schema. */
export type AuthorizationDetail = { type: string } & Record<string, unknown>

const SUPPORTED_RESPONSE_TYPES = ['code']

const list = (value: string | null) => (value ? value.split(' ').filter(Boolean) : [])

/**
 * Everything before a redirect is safe. A bad `client_id` or an unregistered `redirect_uri` must NOT
 * redirect — that turns the provider into an open redirector for attacker-chosen URLs
 * (RFC 6749 §4.1.2.1, RFC 9700 §4.1).
 */
export const parseAuthorizationRequest = async (config: ResolvedConfig, params: URLSearchParams) => {
  const clientId = params.get('client_id')
  if (!clientId) throw new OAuthError('invalid_request', { description: 'client_id is required', spec: 'RFC 6749 §4.1.1' })

  const client = await config.adapter.clients.find(clientId)
  if (!client) throw new OAuthError('invalid_request', { description: `unknown client ${clientId}`, spec: 'RFC 6749 §4.1.2.1' })

  const redirectUri = params.get('redirect_uri')
  if (!redirectUri) throw new OAuthError('invalid_request', { description: 'redirect_uri is required', spec: 'RFC 6749 §4.1.1' })

  // NFR-S2: exact string match. No wildcards, no prefix matching, no port exception.
  if (!client.redirectUris.includes(redirectUri)) {
    throw new OAuthError('invalid_request', {
      description: `redirect_uri ${redirectUri} is not registered for ${clientId}`,
      spec: 'RFC 6749 §3.1.2.3, RFC 9700 §4.1.3'
    })
  }

  return { client, redirectUri }
}

/** Past this point a failure is reported to the client by redirect, as the spec requires. */
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
    throw new OAuthError('unauthorized_client', { description: `client ${client.clientId} may not use response_type ${responseType}` })
  }

  const scopes = list(params.get('scope'))
  if (!scopes.includes('openid')) {
    throw new OAuthError('invalid_scope', { description: 'scope must include openid', spec: 'OIDC Core §3.1.2.1' })
  }
  const unknown = scopes.filter(scope => !config.scopes.includes(scope))
  if (unknown.length) throw new OAuthError('invalid_scope', { description: `unknown scope: ${unknown.join(', ')}` })
  const unallowed = scopes.filter(scope => !client.scopes.includes(scope))
  if (unallowed.length) {
    throw new OAuthError('invalid_scope', { description: `client ${client.clientId} may not request: ${unallowed.join(', ')}` })
  }

  const maxAgeRaw = params.get('max_age')
  const maxAge = maxAgeRaw === null ? undefined : Number(maxAgeRaw)
  if (maxAge !== undefined && (!Number.isInteger(maxAge) || maxAge < 0)) {
    throw new OAuthError('invalid_request', { description: 'max_age must be a non-negative whole number of seconds' })
  }

  const responseMode = params.get('response_mode') ?? 'query'
  if (!['query', 'fragment', 'form_post'].includes(responseMode)) {
    throw new OAuthError('invalid_request', { description: `unsupported response_mode ${responseMode}` })
  }

  return {
    clientId: client.clientId,
    redirectUri,
    responseType,
    responseMode,
    scopes,
    state: params.get('state') ?? undefined,
    nonce: params.get('nonce') ?? undefined,
    codeChallenge: assertChallenge(params.get('code_challenge'), params.get('code_challenge_method')),
    prompt: list(params.get('prompt')),
    maxAge,
    loginHint: params.get('login_hint') ?? undefined,
    acrValues: params.get('acr_values') ? list(params.get('acr_values')) : undefined,
    uiLocales: params.get('ui_locales') ? list(params.get('ui_locales')) : undefined,
    authorizationDetails: parseAuthorizationDetails(config, params.get('authorization_details')),
    raw: params.toString()
  }
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
    const type = (detail as { type?: unknown }).type
    if (typeof type !== 'string') {
      throw new OAuthError('invalid_authorization_details', {
        description: 'every authorization detail needs a string type',
        spec: 'RFC 9396 §2'
      })
    }
    // Only the host knows what its types mean, so it declares them; an unknown one is refused
    // rather than silently granted.
    if (!config.authorizationDetailTypes.includes(type)) {
      throw new OAuthError('invalid_authorization_details', {
        description: `authorization_details type ${type} is not supported`,
        spec: 'RFC 9396 §5'
      })
    }
  }
  return parsed as AuthorizationDetail[]
}

export const redirectTo = (request: AuthorizationRequest, values: Record<string, string>) => {
  const url = new URL(request.redirectUri)
  const target = request.responseMode === 'fragment' ? new URLSearchParams() : url.searchParams
  for (const [key, value] of Object.entries(values)) target.set(key, value)
  if (request.state !== undefined) target.set('state', request.state)
  if (request.responseMode === 'fragment') url.hash = target.toString()
  return url.toString()
}

const missingScopes = (request: AuthorizationRequest, grant: Grant | undefined) =>
  request.scopes.filter(scope => !grant?.scopes.includes(scope))

export type AuthorizationOutcome = { kind: 'redirect'; url: string } | { kind: 'interaction'; id: string; reason: 'login' | 'consent' }

/**
 * Decides what it can and suspends when it cannot (FR-I1). `prompt=none` converts every suspension
 * into the error the client asked for instead (OIDC Core §3.1.2.6).
 */
export const authorize = async (
  config: ResolvedConfig,
  request: AuthorizationRequest,
  session: Session | undefined,
  client?: Client
): Promise<AuthorizationOutcome> => {
  // RFC 9470: a resource server can demand a stronger acr, and honouring it means re-authenticating
  // rather than issuing a token that quietly fails to meet it.
  const acrUnmet = Boolean(request.acrValues?.length && (!session?.acr || !request.acrValues.includes(session.acr)))
  const needsLogin = !session || request.prompt.includes('login') || !isFresh(session, request.maxAge) || acrUnmet

  if (needsLogin) {
    if (request.prompt.includes('none')) {
      throw new OAuthError('login_required', { description: 'no usable session and prompt=none', spec: 'OIDC Core §3.1.2.6' })
    }
    return { kind: 'interaction', id: await suspend(config, request, 'login', undefined, client), reason: 'login' }
  }

  const grant = await config.adapter.grants.findByAccountAndClient(session.accountId, request.clientId)
  const outstanding = missingScopes(request, grant)

  if (outstanding.length || request.prompt.includes('consent')) {
    if (request.prompt.includes('none')) {
      throw new OAuthError('consent_required', {
        description: `consent is needed for: ${outstanding.join(', ') || 'a re-confirmation'}`,
        spec: 'OIDC Core §3.1.2.6'
      })
    }
    return { kind: 'interaction', id: await suspend(config, request, 'consent', session), reason: 'consent' }
  }

  return { kind: 'redirect', url: redirectTo(request, await issueCode(config, request, session, grant as Grant)) }
}

const suspend = async (
  config: ResolvedConfig,
  request: AuthorizationRequest,
  kind: 'login' | 'consent',
  session?: Session,
  client?: Client
) => {
  const id = token()
  // FR-F4: which upstream to use is a decision, so the provider makes it here; performing the round
  // trip is I/O, so the host does that. When nothing decides it, the candidates go to the screen
  // rather than one being guessed.
  const upstream =
    kind === 'login' && config.upstreams.length
      ? selectUpstream(config.upstreams, {
          loginHint: request.loginHint,
          acrValues: request.acrValues,
          allowed: client?.upstreamProviders
        })
      : undefined

  const artifact: Artifact = {
    id,
    kind: 'interaction',
    clientId: request.clientId,
    // A consent interaction already knows who is consenting; a login one does not yet.
    ...(session && { accountId: session.accountId }),
    payload: {
      request: request as unknown as Record<string, unknown>,
      interactionKind: kind,
      ...(upstream && {
        upstream: { chosen: upstream.chosen?.id, candidates: upstream.candidates.map(provider => provider.id) }
      })
    },
    expiresAt: new Date(Date.now() + config.ttl.interaction * 1000)
  }
  await config.adapter.artifacts.upsert(artifact)
  return id
}

const issueCode = async (config: ResolvedConfig, request: AuthorizationRequest, session: Session, grant: Grant) => {
  const code = token()
  await config.adapter.artifacts.upsert({
    id: code,
    kind: 'authorization_code',
    clientId: request.clientId,
    accountId: session.accountId,
    grantId: grant.id,
    payload: {
      redirectUri: request.redirectUri,
      codeChallenge: request.codeChallenge,
      scopes: request.scopes,
      sessionId: session.id,
      ...(request.nonce && { nonce: request.nonce }),
      ...(request.authorizationDetails && { authorizationDetails: request.authorizationDetails })
    },
    expiresAt: new Date(Date.now() + config.ttl.authorizationCode * 1000)
  })
  // FR-C14: unconditional, so a client can tell which provider answered.
  return { code, iss: config.issuer }
}
