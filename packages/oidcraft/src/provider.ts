import { type ProviderConfig, type ResolvedConfig, resolveConfig } from './config'
import type { RequestContext } from './context'
import { authorize, parseAuthorizationRequest, redirectTo, validateAuthorizationRequest } from './endpoints/authorization'
import { discoveryEndpoint } from './endpoints/discovery'
import { endSessionEndpoint, type LogoutNotification } from './endpoints/end-session'
import { introspectionEndpoint } from './endpoints/introspection'
import { jwksEndpoint } from './endpoints/jwks'
import { pushedAuthorizationRequestEndpoint, resolvePushedRequest } from './endpoints/par'
import { revocationEndpoint } from './endpoints/revocation'
import { tokenEndpoint } from './endpoints/token'
import { userinfoEndpoint } from './endpoints/userinfo'
import { errorResponse, OAuthError } from './errors'
import { interactions } from './interactions'
import { applyRequestObject } from './request-object'
import { readSession } from './session'

export type Provider = {
  config: ResolvedConfig
  interactions: ReturnType<typeof interactions>
  /** The whole surface: a WHATWG Request in, a Response out, no I/O of its own (FR-R1, FR-A1). */
  handle(request: Request, context?: Partial<RequestContext>): Promise<Response>
}

type Handler = (config: ResolvedConfig, request: Request, context: RequestContext) => Promise<Response>

const notImplemented =
  (endpoint: string): Handler =>
  async () => {
    throw new OAuthError('temporarily_unavailable', {
      description: `the ${endpoint} endpoint is not implemented yet`,
      spec: 'https://github.com/Fl0r14n/oidcraft/blob/main/PLAN.md',
      status: 501
    })
  }

const seeOther = (url: string, setCookie?: string) =>
  new Response(null, {
    status: 303,
    headers: { location: url, 'cache-control': 'no-store', ...(setCookie && { 'set-cookie': setCookie }) }
  })

const authorizationHandler: Handler = async (config, request) => {
  const url = new URL(request.url)
  const raw = request.method === 'POST' ? new URLSearchParams(await request.text()) : url.searchParams

  const params = await resolveParameters(config, raw)

  // Before a redirect is safe; after it, a failure goes back to the client (RFC 6749 §4.1.2.1).
  const { client, redirectUri } = await parseAuthorizationRequest(config, params)

  // A client registered for PAR must not be able to fall back to the front channel (RFC 9126 §2).
  if (client.requirePushedAuthorizationRequests && !raw.has('request_uri')) {
    throw new OAuthError('invalid_request', {
      description: `client ${client.clientId} must push its authorization requests`,
      spec: 'RFC 9126 §2'
    })
  }

  let validated: ReturnType<typeof validateAuthorizationRequest>
  try {
    validated = validateAuthorizationRequest(config, client, redirectUri, params)
  } catch (error) {
    if (!(error instanceof OAuthError)) throw error
    const url = new URL(redirectUri)
    url.searchParams.set('error', error.code)
    if (error.description) url.searchParams.set('error_description', error.description)
    const state = params.get('state')
    if (state !== null) url.searchParams.set('state', state)
    url.searchParams.set('iss', config.issuer)
    return seeOther(url.toString())
  }

  try {
    const outcome = await authorize(config, validated, await readSession(config, request))
    if (outcome.kind === 'redirect') return seeOther(outcome.url)

    if (!config.interactionUrl) {
      throw new OAuthError('server_error', { description: 'an interaction is required but no interactionUrl is configured (FR-I1)' })
    }
    return seeOther(`${config.interactionUrl}/${outcome.id}`)
  } catch (error) {
    if (!(error instanceof OAuthError)) throw error
    return seeOther(
      redirectTo(validated, { error: error.code, ...(error.description && { error_description: error.description }), iss: config.issuer })
    )
  }
}

/**
 * Back-channel logout tokens are handed to the host rather than delivered here: the core performs
 * no I/O (FR-A1), and a fan-out with retries does not belong inside a request.
 */
export type LogoutDelivery = (notifications: LogoutNotification[]) => void | Promise<void>

const endSessionHandler: Handler = async (config, request) => {
  const session = await readSession(config, request)
  const { response, notifications } = await endSessionEndpoint(config, request, session)
  // From the resolved config, never a module-level pointer: two providers in one process must not
  // be able to reach each other's callback (FR-A1).
  if (notifications.length && config.onLogout) await config.onLogout(notifications)
  return response
}

/**
 * A pushed reference or a signed request object stands in for the parameters. JAR by reference
 * (`request_uri` pointing at the client's own server) is deliberately absent: resolving it means
 * the core fetching a URL the client chose, which it does not do (FR-A1).
 */
const resolveParameters = async (config: ResolvedConfig, raw: URLSearchParams) => {
  const requestUri = raw.get('request_uri')
  if (requestUri) {
    if (!config.features.pushedAuthorizationRequests) {
      throw new OAuthError('invalid_request', { description: 'request_uri is not supported here' })
    }
    return resolvePushedRequest(config, requestUri, raw.get('client_id'))
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

const GET = 'GET'

const routeTable = (config: ResolvedConfig) => {
  const table = new Map<string, { methods: string[]; handle: Handler }>()
  const add = (path: string, methods: string[], handle: Handler) => table.set(path, { methods, handle })

  add(config.routes.discovery, [GET], async cfg => discoveryEndpoint(cfg))
  add(config.routes.oauthMetadata, [GET], async cfg => discoveryEndpoint(cfg))
  add(config.routes.jwks, [GET], async cfg => jwksEndpoint(cfg))
  add(config.routes.authorization, [GET, 'POST'], authorizationHandler)
  add(config.routes.token, ['POST'], async (cfg, req) => tokenEndpoint(cfg, req))
  add(config.routes.userinfo, [GET, 'POST'], async (cfg, req) => userinfoEndpoint(cfg, req))
  add(config.routes.endSession, [GET, 'POST'], endSessionHandler)
  if (config.features.revocation) add(config.routes.revocation, ['POST'], async (cfg, req) => revocationEndpoint(cfg, req))
  if (config.features.introspection) add(config.routes.introspection, ['POST'], async (cfg, req) => introspectionEndpoint(cfg, req))
  if (config.features.dynamicRegistration) add(config.routes.registration, ['POST'], notImplemented('registration'))
  if (config.features.deviceFlow) add(config.routes.deviceAuthorization, ['POST'], notImplemented('device authorization'))
  if (config.features.pushedAuthorizationRequests) {
    add(config.routes.pushedAuthorizationRequest, ['POST'], async (cfg, req) => pushedAuthorizationRequestEndpoint(cfg, req))
  }
  return table
}

/**
 * Validates everything it can here rather than on the first request (NFR-D2), then returns a handler
 * that holds no state across calls — two processes behind a load balancer behave as one (FR-A1).
 */
export const createProvider = (config: ProviderConfig): Provider => {
  const resolved = resolveConfig(config)
  const routes = routeTable(resolved)

  return {
    config: resolved,
    interactions: interactions(resolved),
    async handle(request, context) {
      try {
        const route = routes.get(new URL(request.url).pathname)
        if (!route) return errorResponse(new OAuthError('invalid_request', { description: 'unknown endpoint', status: 404 }))

        if (!route.methods.includes(request.method)) {
          throw new OAuthError('invalid_request', {
            description: `${request.method} is not allowed here; use ${route.methods.join(' or ')}`,
            status: 405,
            headers: { allow: route.methods.join(', ') }
          })
        }

        // The issuer is configuration and is never taken from a header (NFR-S6).
        return await route.handle(resolved, request, { ...context, issuer: resolved.issuer })
      } catch (error) {
        return errorResponse(error)
      }
    }
  }
}
