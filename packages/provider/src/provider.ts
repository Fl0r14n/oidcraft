import type { Session } from '@oidcraft/adapter'
import { withHashedArtifacts } from './artifacts'
import { audit } from './audit'
import { backchannelAuthenticationEndpoint, type CibaDecision, resolveBackchannelRequest } from './authorize/ciba'
import {
  type DeviceSignInContext,
  deviceAuthorizationEndpoint,
  deviceSignIn,
  findByUserCode,
  resolveDeviceCode,
  type UserCodeContext
} from './authorize/device'
import { authorizationEndpoint } from './authorize/endpoint'
import { interactions } from './authorize/interactions'
import { pushedAuthorizationRequestEndpoint } from './authorize/par'
import { withClientMetadata } from './clients/metadata-document'
import { registrationEndpoint } from './clients/registration'
import { type ProviderConfig, type ResolvedConfig, resolveConfig, routePath } from './config'
import type { ClientCertificate, RequestContext } from './context'
import { type Caller, preflight, withCors } from './cors'
import { discoveryEndpoint } from './discovery'
import { errorResponse, OAuthError } from './errors'
import { guarded, reportError } from './hooks'
import { jwksEndpoint } from './keys/jwks'
import { withKeysOnce } from './keys/signer'
import { management } from './management'
import { introspectionEndpoint } from './resource/introspection'
import { revocationEndpoint } from './resource/revocation'
import { userinfoEndpoint } from './resource/userinfo'
import { type AccessTokenVerification, type VerifyAccessTokenOptions, verifyAccessToken } from './resource/verify'
import { endSessionEndpoint } from './session/end-session'
import type { LogoutNotification } from './session/logout'
import { readSession } from './session/session'
import { tokenEndpoint } from './token/endpoint'

export type Provider = {
  config: ResolvedConfig
  interactions: ReturnType<typeof interactions>
  /** Operator-facing, and deliberately not an HTTP route: the host authorizes it (FR-M1). */
  management: ReturnType<typeof management>
  /** The device flow's human half, functions rather than routes because the verification screen is the host's (FR-I3, FR-C7). */
  device: {
    /** Pass the peer address: wrong codes are limited per address (RFC 8628 §5.1). */
    find: (userCode: string, context?: UserCodeContext) => ReturnType<typeof findByUserCode>
    resolve: (
      userCode: string,
      outcome: Parameters<typeof resolveDeviceCode>[2],
      context?: UserCodeContext
    ) => ReturnType<typeof resolveDeviceCode>
    /**
     * With no session, a login interaction that returns to the verification page. Pass the request's
     * `cookie` header and send `setCookie` with the redirect: the interaction is bound to it (FR-I2).
     */
    signIn: (userCode: string, context: DeviceSignInContext) => ReturnType<typeof deviceSignIn>
  }
  /** Who this browser is signed in as here, for the screens no authorization request leads to. */
  session(request: Request): Promise<Session | undefined>
  /** CIBA's out-of-band half, for whatever channel actually asks the person (FR-C17). */
  ciba: { resolve: (authReqId: string, outcome: CibaDecision) => ReturnType<typeof resolveBackchannelRequest> }
  /**
   * For a resource server in this process, in place of introspecting: the presented access token with every check its
   * resource owes it, sender constraint included, or a refusal carrying the ready 401 (FR-C8, FR-C13, FR-C19).
   */
  verifyAccessToken(
    request: Request,
    options?: VerifyAccessTokenOptions,
    context?: Pick<RequestContext, 'clientCertificate'>
  ): Promise<AccessTokenVerification>
  /** A WHATWG Request in, a Response out, no I/O of its own (FR-R1, FR-A1). Of the context it reads only the certificate. */
  handle(request: Request, context?: Pick<RequestContext, 'clientCertificate'>): Promise<Response>
}

type Handler = (config: ResolvedConfig, request: Request, certificate: ClientCertificate | undefined, caller: Caller) => Promise<Response>

/** Back-channel logout tokens go to the host: the core performs no I/O (FR-A1), and a fan-out with retries is no request's job. */
export type LogoutDelivery = (notifications: LogoutNotification[]) => void | Promise<void>

const endSessionHandler: Handler = async (config, request) => {
  const session = await readSession(config, request)
  const { response, notifications, frontChannel, ended } = await endSessionEndpoint(config, request, session)
  // From the resolved config, never module state: two providers in one process must not reach each other's callback (FR-A1).
  if (notifications.length) await guarded(config, request, () => config.onLogout?.(notifications))
  if (frontChannel.length) await guarded(config, request, () => config.onFrontChannelLogout?.(frontChannel))
  if (ended) await guarded(config, request, () => config.onSessionEnd?.(ended, 'logout'))
  return response
}

const GET = 'GET'

const routeTable = (config: ResolvedConfig) => {
  const table = new Map<string, Route>()
  const add = (path: string, methods: string[], handle: Handler) => table.set(path, { methods, handle })

  add(config.routes.discovery, [GET], discoveryEndpoint)
  add(config.routes.oauthMetadata, [GET], discoveryEndpoint)
  add(config.routes.jwks, [GET], jwksEndpoint)
  add(config.routes.authorization, [GET, 'POST'], authorizationEndpoint)
  add(config.routes.token, ['POST'], tokenEndpoint)
  add(config.routes.userinfo, [GET, 'POST'], userinfoEndpoint)
  add(config.routes.endSession, [GET, 'POST'], endSessionHandler)
  if (config.features.revocation) add(config.routes.revocation, ['POST'], revocationEndpoint)
  if (config.features.introspection) add(config.routes.introspection, ['POST'], introspectionEndpoint)
  if (config.features.dynamicRegistration) add(config.routes.registration, ['POST', GET, 'PUT', 'DELETE'], registrationEndpoint)
  if (config.features.deviceFlow) add(config.routes.deviceAuthorization, ['POST'], deviceAuthorizationEndpoint)
  if (config.features.ciba) add(config.routes.backchannelAuthentication, ['POST'], backchannelAuthenticationEndpoint)
  if (config.features.pushedAuthorizationRequests)
    add(config.routes.pushedAuthorizationRequest, ['POST'], pushedAuthorizationRequestEndpoint)
  return table
}

type Route = { methods: string[]; handle: Handler }

const dispatch = async (
  config: ResolvedConfig,
  route: Route,
  request: Request,
  context: Pick<RequestContext, 'clientCertificate'> | undefined,
  caller: Caller
) => {
  try {
    if (!route.methods.includes(request.method)) {
      throw new OAuthError('invalid_request', {
        description: `${request.method} is not allowed here; use ${route.methods.join(' or ')}`,
        status: 405,
        headers: { allow: route.methods.join(', ') }
      })
    }
    return await route.handle(withKeysOnce(config), request, context?.clientCertificate, caller)
  } catch (error) {
    // NFR-D5: only what was not meant.
    if (!(error instanceof OAuthError) || error.status >= 500) {
      await reportError(config, request, error instanceof OAuthError ? (error.cause ?? error) : error)
    }
    if (error instanceof OAuthError && error.event) {
      const { action, ...detail } = error.event
      await guarded(config, request, () => audit(config, action, detail))
    }
    return errorResponse(error)
  }
}

/** Validates the configuration now rather than on the first request (NFR-D2); the handler holds no state across calls (FR-A1). */
export const createProvider = (config: ProviderConfig): Provider => {
  const checked = resolveConfig(config)
  const base = { ...checked, adapter: withHashedArtifacts(checked.adapter) }
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
    verifyAccessToken: (request, options = {}, context) =>
      verifyAccessToken(withKeysOnce(resolved), request, options, context?.clientCertificate),
    async handle(request, context) {
      const path = routePath(resolved, new URL(request.url).pathname)
      const route = routes.get(path)
      if (!route) return errorResponse(new OAuthError('invalid_request', { description: 'unknown endpoint', status: 404 }))
      if (request.method === 'OPTIONS') {
        const answer = preflight(resolved, path, request, route.methods)
        if (answer) return answer
      }
      const caller: Caller = {}
      return withCors(resolved, path, request, await dispatch(resolved, route, request, context, caller), caller)
    }
  }
}
