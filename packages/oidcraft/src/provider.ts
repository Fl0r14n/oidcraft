import { type ProviderConfig, type ResolvedConfig, resolveConfig } from './config'
import type { RequestContext } from './context'
import { discoveryEndpoint } from './endpoints/discovery'
import { jwksEndpoint } from './endpoints/jwks'
import { errorResponse, OAuthError } from './errors'

export type Provider = {
  config: ResolvedConfig
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

const GET = 'GET'

const routeTable = (config: ResolvedConfig) => {
  const table = new Map<string, { methods: string[]; handle: Handler }>()
  const add = (path: string, methods: string[], handle: Handler) => table.set(path, { methods, handle })

  add(config.routes.discovery, [GET], async cfg => discoveryEndpoint(cfg))
  add(config.routes.oauthMetadata, [GET], async cfg => discoveryEndpoint(cfg))
  add(config.routes.jwks, [GET], async cfg => jwksEndpoint(cfg))
  add(config.routes.authorization, [GET, 'POST'], notImplemented('authorization'))
  add(config.routes.token, ['POST'], notImplemented('token'))
  add(config.routes.userinfo, [GET, 'POST'], notImplemented('userinfo'))
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
