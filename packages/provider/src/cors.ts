import type { Client } from '@oidcraft/adapter'
import type { ResolvedConfig } from './config'

/** What a page on any origin may read: it is published for exactly that. */
const publicRoutes = (config: ResolvedConfig) => [config.routes.discovery, config.routes.oauthMetadata, config.routes.jwks]

/** What a browser client calls directly. Everything else is navigated to, or is the host's. */
const clientRoutes = (config: ResolvedConfig) => [
  config.routes.token,
  config.routes.userinfo,
  config.routes.revocation,
  config.routes.introspection
]

const EXPOSED = 'www-authenticate, dpop-nonce'

/**
 * The client a request came from, as its handler found it: by the credentials it presented, or at
 * UserInfo by its access token. Recorded on finding it, so an error the handler throws afterwards is
 * still readable by that client's pages.
 */
export type Caller = { client?: Client }

const allowed = (caller: Caller, origin: string) =>
  Boolean(caller.client?.redirectUris.some(uri => URL.canParse(uri) && new URL(uri).origin === origin))

/**
 * A preflight on a client route is answered for any origin: it only lets the browser send what a
 * form post from that origin already could. Whether the page may *read* the answer is decided on the
 * real response, by the client it came from.
 */
export const preflight = (config: ResolvedConfig, path: string, request: Request, methods: string[]) => {
  const origin = request.headers.get('origin')
  if (!origin || (!publicRoutes(config).includes(path) && !clientRoutes(config).includes(path))) return undefined
  return new Response(null, {
    status: 204,
    headers: {
      'access-control-allow-origin': publicRoutes(config).includes(path) ? '*' : origin,
      'access-control-allow-methods': methods.join(', '),
      'access-control-allow-headers': 'authorization, content-type, dpop',
      'access-control-max-age': '600',
      vary: 'origin'
    }
  })
}

/**
 * Lets a page read the response only when it is on the origin of one of the calling client's
 * registered redirect URIs. Nothing is configured: the registration already says where the client lives.
 */
export const withCors = (config: ResolvedConfig, path: string, request: Request, response: Response, caller: Caller) => {
  const origin = request.headers.get('origin')
  if (!origin) return response
  if (publicRoutes(config).includes(path)) {
    response.headers.set('access-control-allow-origin', '*')
    return response
  }
  if (!clientRoutes(config).includes(path)) return response
  response.headers.append('vary', 'origin')
  if (allowed(caller, origin)) {
    response.headers.set('access-control-allow-origin', origin)
    response.headers.set('access-control-expose-headers', EXPOSED)
  }
  return response
}
