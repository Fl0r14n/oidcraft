/// <reference types="bun" />
import { serve } from 'bun'

const production = Bun.env.NODE_ENV === 'production'
const port = Number(Bun.env.CLIENT_PORT ?? 3000)

// A route, not a file read: only the bundler substitutes the script and style tags.
const server = production
  ? serve({
      port,
      routes: {
        '/assets/*': { dir: `${import.meta.dir}/dist/assets` },
        '/*': new Response(Bun.file(`${import.meta.dir}/dist/index.html`))
      }
    })
  : serve({ port, routes: { '/*': (await import('./index.html')).default } })

console.log(`client on http://localhost:${server.port}`)
