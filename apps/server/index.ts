/// <reference types="bun" />
import { serve } from 'bun'
import { issuer } from './src/env'

const port = Number(Bun.env.SERVER_PORT ?? 3001)

// The core is fetch-native, so Bun.serve mounts it directly: no adapter on this runtime
// (ARCHITECTURE.md §3.1). the `oidcraft/node` entry exists only for node:http hosts.
const server = serve({
  port,
  fetch: async request => new Response(`oidcraft OP scaffold — ${issuer()} — ${new URL(request.url).pathname}`, { status: 501 })
})

console.log(`op on http://localhost:${server.port}`)
