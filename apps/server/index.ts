/// <reference types="bun" />
import { serve } from 'bun'
import { provider } from './src/provider'

const port = Number(Bun.env.SERVER_PORT ?? 3001)

// Bun.serve takes the core's handler directly: on this runtime there is no bridge, only the context
// provider for what Request does not carry (ARCHITECTURE.md §3.1).
const server = serve({
  port,
  fetch: request => provider.handle(request)
})

console.log(`op on http://localhost:${server.port}`)
console.log(`  discovery  http://localhost:${server.port}/.well-known/openid-configuration`)
console.log(`  jwks       http://localhost:${server.port}/jwks`)
