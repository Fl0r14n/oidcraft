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

// Set as soon as the handler finds the client, so an error thrown afterwards is still readable by that client's pages.
export type Caller = { client?: Client }

const allowed = (caller: Caller, origin: string) =>
  Boolean(caller.client?.redirectUris.some(uri => URL.canParse(uri) && new URL(uri).origin === origin))

// Any origin's preflight is answered: it permits only what a form post could send. Reading is decided on the real response.
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

// Readable only from the origin of one of the calling client's registered redirect URIs.
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
