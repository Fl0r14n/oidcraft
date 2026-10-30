/// <reference types="bun" />
import { ASSETS, assets } from '@oidcraft/ui'
import { serve } from 'bun'
import { bunContext } from 'oidcraft/runtimes/bun'
import { accountApi } from './src/account/api'
import { adminApi } from './src/admin/api'
import { fapiDemoRoutes } from './src/fapi/demo'
import { brokerCallback } from './src/interaction/broker'
import { routesFor } from './src/interaction/routes'
import { optional } from './src/op/env'
import { control } from './src/op/provider'
import { realms, realmsEnabled, siteOf } from './src/op/realms'

const port = Number(Bun.env.SERVER_PORT ?? 3001)
// Discovery 1.0 §3 and RFC 8414 §2 require an https issuer even on loopback.
const cert = optional('SERVER_TLS_CERT')
const key = optional('SERVER_TLS_KEY')

// A route, not a file read: only the bundler substitutes the script and style tags.
const admin = (await import('./src/admin/index.html')).default
const account = (await import('./src/account/index.html')).default

// Bun.serve takes the core's handler directly: on this runtime there is no bridge, only the context
// provider for what Request does not carry (ARCHITECTURE.md §3.1).
const server = serve({
  port,
  ...(cert && key && { tls: { cert: Bun.file(cert), key: Bun.file(key) } }),
  routes: {
    // More specific than '/admin/*', so the API is not swallowed by the SPA shell.
    '/admin/api/*': request =>
      adminApi(control.provider, realms, request, new URL(request.url)).then(response => response ?? new Response(null, { status: 404 })),
    [ASSETS]: assets,
    '/admin': admin,
    '/admin/*': admin,
    '/account/api/*': request =>
      accountApi(request, new URL(request.url)).then(response => response ?? new Response(null, { status: 404 })),
    '/account': account,
    '/account/*': account
  },
  async fetch(request, server) {
    const url = new URL(request.url)
    const site = await siteOf(request)
    if (!site) return new Response('No such realm', { status: 404 })
    const { provider, screens } = site
    const routes = routesFor(site)
    const context = bunContext(provider.config.issuer, server)(request)
    if (url.pathname.startsWith('/interaction/')) {
      const response = await routes.interactionRoutes(request, url)
      if (response) return response
    }
    if (url.pathname === '/reset') return routes.resetRoutes(request, url)
    if (url.pathname === '/federation/callback' && site.brokering) {
      const response = await brokerCallback(request, url)
      if (response) return response
    }
    if (url.pathname.startsWith('/fapi-demo') && site === control) {
      const response = await fapiDemoRoutes(provider, url)
      if (response) return response
    }
    if (url.pathname === '/device' || url.pathname === '/device/decide') {
      const response = await routes.deviceRoutes(request, url, context.clientIp)
      if (response) return response
    }
    const response = await provider.handle(request, context)
    if (url.pathname === '/authorize' && response.status >= 400 && response.headers.get('content-type')?.includes('json')) {
      const { error, error_description } = await response.json()
      return screens.error(error, error_description, response.status)
    }
    return response
  }
})

console.log(`op on http://localhost:${server.port}`)
console.log(`  discovery  http://localhost:${server.port}/.well-known/openid-configuration`)
console.log(`  jwks       http://localhost:${server.port}/jwks`)
console.log(`  admin      http://localhost:${server.port}/admin`)
console.log(`  account    http://localhost:${server.port}/account`)
console.log(`  device     http://localhost:${server.port}/device`)
if (realmsEnabled) console.log(`  realms     http://<realm>.localhost:${server.port} — create them in the admin`)
