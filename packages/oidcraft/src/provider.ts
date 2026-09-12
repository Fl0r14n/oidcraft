import { type ProviderConfig, type ResolvedConfig, resolveConfig } from './config'
import type { RequestContext } from './context'
import { authorize, parseAuthorizationRequest, redirectTo, validateAuthorizationRequest } from './endpoints/authorization'
import { discoveryEndpoint } from './endpoints/discovery'
import { jwksEndpoint } from './endpoints/jwks'
import { tokenEndpoint } from './endpoints/token'
import { userinfoEndpoint } from './endpoints/userinfo'
import { errorResponse, OAuthError } from './errors'
import { interactions } from './interactions'
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
  const params = request.method === 'POST' ? new URLSearchParams(await request.text()) : url.searchParams

  // Before a redirect is safe; after it, a failure goes back to the client (RFC 6749 §4.1.2.1).
  const { client, redirectUri } = await parseAuthorizationRequest(config, params)

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
  add(config.routes.endSession, [GET, 'POST'], notImplemented('end session'))
  if (config.features.revocation) add(config.routes.revocation, ['POST'], notImplemented('revocation'))
  if (config.features.introspection) add(config.routes.introspection, ['POST'], notImplemented('introspection'))
  if (config.features.dynamicRegistration) add(config.routes.registration, ['POST'], notImplemented('registration'))
  if (config.features.deviceFlow) add(config.routes.deviceAuthorization, ['POST'], notImplemented('device authorization'))
  if (config.features.pushedAuthorizationRequests) {
    add(config.routes.pushedAuthorizationRequest, ['POST'], notImplemented('pushed authorization request'))
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
