import type { ResolvedConfig } from '../config'
import { OAuthError } from '../errors'
import { readForm } from '../form'
import { readArtifact } from '../payloads'
import { assertFapiClient, underFapi } from '../profile/fapi'
import { bindBrowser } from '../session/browser'
import { readSession } from '../session/session'
import {
  authorizationResponse,
  authorize,
  parseAuthorizationRequest,
  RESPONSE_MODES,
  type ResponseTarget,
  validateAuthorizationRequest
} from './authorization'
import { resolvePushedRequest } from './par'
import { applyRequestObject } from './request-object'

const seeOther = (url: string, setCookie?: string) =>
  new Response(null, {
    status: 303,
    headers: { location: url, 'cache-control': 'no-store', ...(setCookie && { 'set-cookie': setCookie }) }
  })

const errorValues = (error: OAuthError) => ({ error: error.code, ...(error.description && { error_description: error.description }) })

/** An interaction's error answer, single-use, delivered in the mode the request asked for (FR-C14). */
const deliverStoredResponse = async (config: ResolvedConfig, id: string) => {
  const artifact = await readArtifact(config.adapter.artifacts, 'authorization_response', id)
  if (!artifact || !(await config.adapter.artifacts.consume('authorization_response', id))) {
    throw new OAuthError('invalid_request', {
      description: 'this authorization response is unknown, expired or already delivered',
      spec: 'FR-I2'
    })
  }
  return authorizationResponse(config.issuer, artifact.payload.target, artifact.payload.values)
}

/** The authorization endpoint (FR-C1): the redirect target is checked before anything is sent back to it (RFC 9700 §4.11). */
export const authorizationEndpoint = async (config: ResolvedConfig, request: Request) => {
  const url = new URL(request.url)
  const raw = request.method === 'POST' ? await readForm(request) : url.searchParams

  const stored = raw.get('response')
  if (stored && !raw.has('client_id')) return deliverStoredResponse(config, stored)

  const params = await resolveParameters(config, raw)

  // Before a redirect is safe; after it, a failure goes back to the client (RFC 6749 §4.1.2.1).
  const { client, redirectUri } = await parseAuthorizationRequest(config, params)

  const fapi = underFapi(config, client)
  if (fapi) assertFapiClient(config, client)
  // A client registered for PAR must not be able to fall back to the front channel (RFC 9126 §2).
  if ((client.requirePushedAuthorizationRequests || fapi) && !raw.has('request_uri')) {
    throw new OAuthError('invalid_request', {
      description: `client ${client.clientId} must push its authorization requests`,
      spec: fapi ? 'FAPI 2.0 Security Profile §5.3.2.2' : 'RFC 9126 §2'
    })
  }

  let validated: ReturnType<typeof validateAuthorizationRequest>
  try {
    validated = {
      ...validateAuthorizationRequest(config, client, redirectUri, params),
      // RFC 9101: a signed request resumes by reference too, or its parameters cross the front channel editable.
      ...((raw.has('request_uri') || raw.has('request')) && { pushed: true as const })
    }
  } catch (error) {
    if (!(error instanceof OAuthError)) throw error
    const mode = params.get('response_mode')
    const target: ResponseTarget = {
      redirectUri,
      responseMode: mode && RESPONSE_MODES.includes(mode) ? mode : 'query',
      state: params.get('state') ?? undefined
    }
    return authorizationResponse(config.issuer, target, errorValues(error))
  }

  try {
    const { browser, setCookie } = await bindBrowser(config, request.headers.get('cookie'))
    const outcome = await authorize(config, validated, await readSession(config, request), client, browser)
    if (outcome.kind === 'response') return authorizationResponse(config.issuer, validated, outcome.values)

    return seeOther(`${config.interactionUrl}/${outcome.id}`, setCookie)
  } catch (error) {
    if (!(error instanceof OAuthError)) throw error
    return authorizationResponse(config.issuer, validated, errorValues(error))
  }
}

// JAR by reference is deliberately absent: resolving it means fetching a URL the client chose (FR-A1).
const resolveParameters = async (config: ResolvedConfig, raw: URLSearchParams) => {
  const requestUri = raw.get('request_uri')
  if (requestUri && raw.has('request')) {
    throw new OAuthError('invalid_request', { description: 'request and request_uri must not be sent together', spec: 'RFC 9101 §5' })
  }
  if (requestUri && !raw.get('client_id')) {
    throw new OAuthError('invalid_request', { description: 'a request_uri needs the client_id alongside it', spec: 'RFC 9126 §4' })
  }
  if (requestUri) {
    if (config.features.pushedAuthorizationRequests) return resolvePushedRequest(config, requestUri, raw.get('client_id'))
    // PAR off, the only reference is the one that resumes a signed request after an interaction; anything else is unsupported.
    // Only a refusal means "not one of ours"; a store that failed is the host's to hear about (NFR-D5).
    const resumed = await resolvePushedRequest(config, requestUri, raw.get('client_id')).catch(error => {
      if (error instanceof OAuthError) return undefined
      throw error
    })
    if (!resumed) {
      throw new OAuthError('request_uri_not_supported', { description: 'request_uri is not supported here', spec: 'OIDC Core §3.1.2.6' })
    }
    return resumed
  }

  if (raw.has('request')) {
    const clientId = raw.get('client_id')
    const client = clientId ? await config.adapter.clients.find(clientId) : undefined
    if (!client)
      throw new OAuthError('invalid_request', { description: 'a request object needs a client_id alongside it', spec: 'RFC 9101 §5' })
    return applyRequestObject(config, client, raw)
  }

  return raw
}
