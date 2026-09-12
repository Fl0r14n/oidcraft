/// <reference types="bun" />
import { serve } from 'bun'
import { adminApi } from './src/admin/api'
import { interactionRoutes } from './src/interaction/routes'
import { provider } from './src/provider'

const port = Number(Bun.env.SERVER_PORT ?? 3001)

// A route, not a file read: only the bundler substitutes the script and style tags.
const admin = (await import('./src/admin/index.html')).default

// Bun.serve takes the core's handler directly: on this runtime there is no bridge, only the context
// provider for what Request does not carry (ARCHITECTURE.md §3.1).
const server = serve({
  port,
  routes: {
    // More specific than '/admin/*', so the API is not swallowed by the SPA shell.
    '/admin/api/*': request =>
      adminApi(provider, request, new URL(request.url)).then(response => response ?? new Response(null, { status: 404 })),
    '/admin': admin,
    '/admin/*': admin
  },
  async fetch(request) {
    const url = new URL(request.url)
    if (url.pathname.startsWith('/interaction/')) {
      const response = await interactionRoutes(request, url)
      if (response) return response
    }
    return provider.handle(request)
  }
})

console.log(`op on http://localhost:${server.port}`)
console.log(`  discovery  http://localhost:${server.port}/.well-known/openid-configuration`)
console.log(`  jwks       http://localhost:${server.port}/jwks`)
console.log(`  admin      http://localhost:${server.port}/admin`)
