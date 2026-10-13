/// <reference types="bun" />
import { serve } from 'bun'
import { render } from './src/entry-server'

// dev IdPs are routinely fronted by a self-signed cert; the SSR pass must not die on it
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'

const production = Bun.env.NODE_ENV === 'production'
const port = Number(Bun.env.PORT || 3000)
const key = Bun.file('../../.cert/key.pem')
const cert = Bun.file('../../.cert/cert.pem')
const tls = (await key.exists()) && (await cert.exists()) ? { key, cert } : undefined

// Substituted into the client bundle as whole `process.env.X` literals, from the repository-root
// `.env`. Only this prefix reaches a browser (ARCHITECTURE.md §9.1), and every name is defined even
// when unset, or the literal survives into the browser, where `process` does not exist.
const PUBLIC = [
  'OIDCRAFT_PUBLIC_ISSUER',
  'OIDCRAFT_PUBLIC_CLIENT_ID',
  'OIDCRAFT_PUBLIC_SCOPE',
  'OIDCRAFT_PUBLIC_THEME',
  'OIDCRAFT_PUBLIC_REACT_ORIGIN'
]
const define = {
  'process.env.NODE_ENV': JSON.stringify(production ? 'production' : 'development'),
  ...Object.fromEntries(
    PUBLIC.map(name => [`process.env.${name}`, Bun.env[name] === undefined ? 'undefined' : JSON.stringify(Bun.env[name])])
  )
}

/**
 * The client half, bundled once per process. In development `bun --watch` restarts the process on
 * any change to what the server imports — which is all of `src/` but `entry-client.tsx` — and the
 * page reloads when its socket to the old process drops. There is no Fast Refresh: Bun's
 * hot-reloading dev server only serves static HTML, and this page is server-rendered.
 */
const built = await Bun.build({
  entrypoints: ['./src/entry-client.tsx'],
  target: 'browser',
  define,
  minify: production,
  sourcemap: production ? 'none' : 'inline'
})
if (!built.success) {
  for (const log of built.logs) console.error(log)
  process.exit(1)
}
const entry = built.outputs.find(output => output.kind === 'entry-point')
if (!entry) throw new Error('the client build produced no entry point')
const client = await entry.text()

const RELOAD = '/__reload'
// Reconnects until the restarted process answers, then reloads: the old one closed the socket.
const reloader = `<script>(() => {
  const connect = () => {
    const socket = new WebSocket(location.origin.replace(/^http/, 'ws') + '${RELOAD}')
    socket.onopen = () => { if (window.__reloading) location.reload() }
    socket.onclose = () => { window.__reloading = true; setTimeout(connect, 300) }
  }
  connect()
})()</script>`

const template = await Bun.file(new URL('./index.html', import.meta.url)).text()

const server = serve({
  port,
  ...(tls && { tls }),
  routes: {
    '/client.js': () => new Response(client, { headers: { 'content-type': 'text/javascript; charset=utf-8' } })
  },
  async fetch(request, server) {
    const url = new URL(request.url)
    if (!production && url.pathname === RELOAD && server.upgrade(request)) return undefined
    try {
      const locale = request.headers.get('accept-language')?.split(',')[0]?.split('-')[0]
      const { body, head } = await render(url, locale)
      // The template's two halves around React's stream: the head goes out before rendering finishes.
      const [before, after] = template.replace('<!--app-head-->', head + (production ? '' : reloader)).split('<!--app-html-->')
      const encoder = new TextEncoder()
      const page = body.pipeThrough(
        new TransformStream<Uint8Array, Uint8Array>({
          start: controller => controller.enqueue(encoder.encode(before)),
          flush: controller => controller.enqueue(encoder.encode(after))
        })
      )
      return new Response(page, { headers: { 'content-type': 'text/html; charset=utf-8' } })
    } catch (error) {
      console.error('SSR error:', error)
      return new Response(production ? 'Internal Server Error' : String((error as Error).stack), { status: 500 })
    }
  },
  websocket: { message() {} }
})

console.log(`Listening on ${tls ? 'https' : 'http'}://localhost:${server.port}`)
