import {
  authorizationResponse,
  authorize,
  parseAuthorizationRequest,
  RESPONSE_MODES,
  type ResponseTarget,
  validateAuthorizationRequest
} from './authorize/authorization'
import { backchannelAuthenticationEndpoint, type CibaDecision, resolveBackchannelRequest } from './authorize/ciba'
import { deviceAuthorizationEndpoint, deviceSignIn, findByUserCode, resolveDeviceCode, type UserCodeContext } from './authorize/device'
import { interactions } from './authorize/interactions'
import { pushedAuthorizationRequestEndpoint, resolvePushedRequest } from './authorize/par'
import { applyRequestObject } from './authorize/request-object'
import { withClientMetadata } from './clients/metadata-document'
import { registrationEndpoint } from './clients/registration'
import { type ProviderConfig, type ResolvedConfig, resolveConfig, routePath } from './config'
import type { RequestContext } from './context'
import { preflight, withCors } from './cors'
import { discoveryEndpoint } from './discovery'
import { errorResponse, OAuthError } from './errors'
import { jwksEndpoint } from './keys/jwks'
import { management } from './management'
import { introspectionEndpoint } from './resource/introspection'
import { revocationEndpoint } from './resource/revocation'
import { userinfoEndpoint } from './resource/userinfo'
import { endSessionEndpoint } from './session/end-session'
import type { LogoutNotification } from './session/logout'
import { readSession } from './session/session'
import { tokenEndpoint } from './token/endpoint'
import type { Session } from './types'

export type Provider = {
  config: ResolvedConfig
  interactions: ReturnType<typeof interactions>
  /** Operator-facing, and deliberately not an HTTP route: the host authorizes it (FR-M1). */
  management: ReturnType<typeof management>
  /**
   * The device flow's human half. The verification screen is the host's (FR-I3), so these are
   * functions rather than routes: look up what was typed, then approve or deny it (FR-C7).
   */
  device: {
    /** Pass the peer address: wrong codes are limited per address (RFC 8628 §5.1). */
    find: (userCode: string, context?: UserCodeContext) => ReturnType<typeof findByUserCode>
    resolve: (
      userCode: string,
      outcome: Parameters<typeof resolveDeviceCode>[2],
      context?: UserCodeContext
    ) => ReturnType<typeof resolveDeviceCode>
    /** No session to approve with: a login interaction that returns to the verification page. */
    signIn: (userCode: string, context?: UserCodeContext) => ReturnType<typeof deviceSignIn>
  }
  /** Who this browser is signed in as here, for the screens no authorization request leads to. */
  session(request: Request): Promise<Session | undefined>
  /** CIBA's out-of-band half, for whatever channel actually asks the person (FR-C17). */
  ciba: { resolve: (authReqId: string, outcome: CibaDecision) => ReturnType<typeof resolveBackchannelRequest> }
  /** The whole surface: a WHATWG Request in, a Response out, no I/O of its own (FR-R1, FR-A1). */
  handle(request: Request, context?: Partial<RequestContext>): Promise<Response>
}

type Handler = (config: ResolvedConfig, request: Request, context: RequestContext) => Promise<Response>

const seeOther = (url: string, setCookie?: string) =>
  new Response(null, {
    status: 303,
    headers: { location: url, 'cache-control': 'no-store', ...(setCookie && { 'set-cookie': setCookie }) }
  })

const errorValues = (error: OAuthError) => ({ error: error.code, ...(error.description && { error_description: error.description }) })

/** An interaction's error answer, single-use, delivered in the mode the request asked for (FR-C14). */
const deliverStoredResponse = async (config: ResolvedConfig, id: string) => {
  const artifact = await config.adapter.artifacts.find('authorization_response', id)
  if (!artifact || !(await config.adapter.artifacts.consume('authorization_response', id))) {
    throw new OAuthError('invalid_request', { description: 'this authorization response is unknown, expired or already delivered' })
  }
  return authorizationResponse(config.issuer, artifact.payload.target as ResponseTarget, artifact.payload.values as Record<string, string>)
}

const authorizationHandler: Handler = async (config, request) => {
  const url = new URL(request.url)
  const raw = request.method === 'POST' ? new URLSearchParams(await request.text()) : url.searchParams

  const stored = raw.get('response')
  if (stored && !raw.has('client_id')) return deliverStoredResponse(config, stored)

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
    validated = {
      ...validateAuthorizationRequest(config, client, redirectUri, params),
      ...(raw.has('request_uri') && { pushed: true as const })
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
    const outcome = await authorize(config, validated, await readSession(config, request), client)
    if (outcome.kind === 'response') return authorizationResponse(config.issuer, validated, outcome.values)

    if (!config.interactionUrl) {
      throw new OAuthError('server_error', { description: 'an interaction is required but no interactionUrl is configured (FR-I1)' })
    }
    return seeOther(`${config.interactionUrl}/${outcome.id}`)
  } catch (error) {
    if (!(error instanceof OAuthError)) throw error
    return authorizationResponse(config.issuer, validated, errorValues(error))
  }
}

/**
 * Back-channel logout tokens are handed to the host rather than delivered here: the core performs
 * no I/O (FR-A1), and a fan-out with retries does not belong inside a request.
 */
export type LogoutDelivery = (notifications: LogoutNotification[]) => void | Promise<void>

const endSessionHandler: Handler = async (config, request) => {
  const session = await readSession(config, request)
  const { response, notifications, frontChannel } = await endSessionEndpoint(config, request, session)
  // From the resolved config, never a module-level pointer: two providers in one process must not
  // be able to reach each other's callback (FR-A1).
  if (notifications.length && config.onLogout) await config.onLogout(notifications)
  // The iframe page belongs to the host, so the URLs are handed over rather than rendered here.
  if (frontChannel.length && config.onFrontChannelLogout) await config.onFrontChannelLogout(frontChannel)
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
  const table = new Map<string, Route>()
  const add = (path: string, methods: string[], handle: Handler) => table.set(path, { methods, handle })

  add(config.routes.discovery, [GET], async cfg => discoveryEndpoint(cfg))
  add(config.routes.oauthMetadata, [GET], async cfg => discoveryEndpoint(cfg))
  add(config.routes.jwks, [GET], async cfg => jwksEndpoint(cfg))
  add(config.routes.authorization, [GET, 'POST'], authorizationHandler)
  add(config.routes.token, ['POST'], async (cfg, req, ctx) => tokenEndpoint(cfg, req, ctx.clientCertificate))
  add(config.routes.userinfo, [GET, 'POST'], async (cfg, req, ctx) => userinfoEndpoint(cfg, req, ctx.clientCertificate))
  add(config.routes.endSession, [GET, 'POST'], endSessionHandler)
  if (config.features.revocation)
    add(config.routes.revocation, ['POST'], async (cfg, req, ctx) => revocationEndpoint(cfg, req, ctx.clientCertificate))
  if (config.features.introspection)
    add(config.routes.introspection, ['POST'], async (cfg, req, ctx) => introspectionEndpoint(cfg, req, ctx.clientCertificate))
  if (config.features.dynamicRegistration) {
    add(config.routes.registration, ['POST', GET, 'PUT', 'DELETE'], async (cfg, req) => registrationEndpoint(cfg, req))
  }
  if (config.features.deviceFlow) {
    add(config.routes.deviceAuthorization, ['POST'], async (cfg, req, ctx) => deviceAuthorizationEndpoint(cfg, req, ctx.clientCertificate))
  }
  if (config.features.ciba) {
    add(config.routes.backchannelAuthentication, ['POST'], async (cfg, req, ctx) =>
      backchannelAuthenticationEndpoint(cfg, req, ctx.clientCertificate)
    )
  }
  if (config.features.pushedAuthorizationRequests) {
    add(config.routes.pushedAuthorizationRequest, ['POST'], async (cfg, req, ctx) =>
      pushedAuthorizationRequestEndpoint(cfg, req, ctx.clientCertificate)
    )
  }
  return table
}

type Route = { methods: string[]; handle: Handler }

const dispatch = async (config: ResolvedConfig, route: Route, request: Request, context: Partial<RequestContext> | undefined) => {
  try {
    if (!route.methods.includes(request.method)) {
      throw new OAuthError('invalid_request', {
        description: `${request.method} is not allowed here; use ${route.methods.join(' or ')}`,
        status: 405,
        headers: { allow: route.methods.join(', ') }
      })
    }
    // The issuer is configuration and is never taken from a header (NFR-S6).
    return await route.handle(config, request, { ...context, issuer: config.issuer })
  } catch (error) {
    return errorResponse(error)
  }
}

/**
 * Validates everything it can here rather than on the first request (NFR-D2), then returns a handler
 * that holds no state across calls — two processes behind a load balancer behave as one (FR-A1).
 */
export const createProvider = (config: ProviderConfig): Provider => {
  const base = resolveConfig(config)
  const resolved = base.resolveClientMetadata ? { ...base, adapter: withClientMetadata(base, base.resolveClientMetadata) } : base
  const routes = routeTable(resolved)

  return {
    config: resolved,
    interactions: interactions(resolved),
    management: management(resolved),
    device: {
      find: (userCode, context) => findByUserCode(resolved, userCode, context),
      resolve: (userCode, outcome, context) => resolveDeviceCode(resolved, userCode, outcome, context),
      signIn: (userCode, context) => deviceSignIn(resolved, userCode, context)
    },
    session: request => readSession(resolved, request),
    ciba: { resolve: (authReqId, outcome) => resolveBackchannelRequest(resolved, authReqId, outcome) },
    async handle(request, context) {
      const path = routePath(resolved, new URL(request.url).pathname)
      const route = routes.get(path)
      if (!route) return errorResponse(new OAuthError('invalid_request', { description: 'unknown endpoint', status: 404 }))
      if (request.method === 'OPTIONS') {
        const answer = preflight(resolved, path, request, route.methods)
        if (answer) return answer
      }
      // The handler reads the body; deciding CORS afterwards needs its own copy (cors.ts).
      const original = request.headers.has('origin') ? request.clone() : request
      return withCors(resolved, path, original, await dispatch(resolved, route, request, context))
    }
  }
}
