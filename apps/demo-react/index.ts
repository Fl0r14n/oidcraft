import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { Writable } from 'node:stream'
import { fileURLToPath, serve } from 'bun'

// dev IdPs are routinely fronted by a self-signed cert; the SSR pass must not die on it
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'

let key: Buffer | undefined
let cert: Buffer | undefined
try {
  key = readFileSync('../../.cert/key.pem')
  cert = readFileSync('../../.cert/cert.pem')
} catch {
  /* no certs — fall back to plain http */
}

const tls = (key && cert && { key, cert }) || undefined
const port = process.env.PORT || 3000
const mode = process.env.NODE_ENV || 'development'
const root = dirname(fileURLToPath(import.meta.url))
const path = (p: string) => resolve(root, p)

const { createServer } = await import('vite')
// HMR works here, but only because vite.config.ts pins `server.hmr.host`/`protocol`: the client would
// otherwise derive its websocket target from the page origin, and that port belongs to Bun.serve, not
// to Vite.
const vite = await createServer({
  mode,
  server: { middlewareMode: true },
  appType: 'custom'
})

/** Vite's middleware speaks Node's `http` req/res; `Bun.serve` speaks `Request`/`Response`. This
 * adapts one to the other by collecting the writes into a buffer, and resolves `null` when the
 * middleware declines the request — which is the signal to fall through to SSR. */
const viteMiddleware = (req: Request, url: URL) =>
  new Promise<Response | null>(resolveResponse => {
    const chunks: Buffer[] = []
    const res: any = new Writable({
      write(chunk, _encoding, callback) {
        chunks.push(Buffer.from(chunk))
        callback()
      },
      final(callback) {
        const body = chunks.length > 0 ? Buffer.concat(chunks) : undefined
        resolveResponse(new Response(body, { status: res.statusCode || 200, headers: res.headers }))
        callback()
      },
      destroy(err, callback) {
        if (err) {
          console.error('Stream destroyed with error:', err)
        }
        callback(err)
      }
    })

    res.headers = {}
    res.getHeader = (name: string) => res.headers[name.toLowerCase()]
    res.setHeader = (name: string, value: string | string[]) => {
      res.headers[name.toLowerCase()] = value
    }
    res.appendHeader = (name: string, value: string) => {
      const key = name.toLowerCase()
      const existing = res.headers[key]
      if (existing === undefined) {
        res.headers[key] = value
      } else {
        res.headers[key] = Array.isArray(existing) ? [...existing, value] : [existing, value]
      }
    }
    res.writeHead = (statusCode: number, headers: any) => {
      res.statusCode = statusCode
      if (headers) {
        for (const [k, value] of Object.entries(headers)) {
          res.headers[k.toLowerCase()] = value
        }
      }
    }

    vite.middlewares(
      {
        url: url.pathname + url.search,
        method: req.method,
        headers: Object.fromEntries(req.headers.entries())
      } as any,
      res,
      () => resolveResponse(null)
    )
  })

const server = serve({
  async fetch(req) {
    const url = new URL(req.url)

    if (url.pathname === '/.well-known/appspecific/com.chrome.devtools.json') {
      return Response.json({ mappings: [{ url: `${url.origin}/`, path: `${root}/` }] })
    }

    const viteResponse = await viteMiddleware(req, url)
    if (viteResponse) {
      return viteResponse
    }

    try {
      const template = readFileSync(path('index.html'), 'utf-8')
      const view = await vite.transformIndexHtml(url.pathname, template)
      const { render } = await vite.ssrLoadModule('/src/entry-server.tsx')
      const locale = req.headers.get('accept-language')?.split(',')[0]?.split('-')[0]
      const { body, head } = await render(url, locale)
      const html = view.replace('<!--app-head-->', head).replace('<!--app-html-->', body)
      return new Response(html, { headers: { 'Content-Type': 'text/html' } })
    } catch (e: any) {
      vite.ssrFixStacktrace(e)
      console.error('SSR Error:', e)
      return new Response(e.stack, { status: 500 })
    }
  },
  port,
  ...(tls && { tls }),
  error(error) {
    console.error(error)
    return new Response('Internal Server Error', { status: 500 })
  }
})

console.log(`Listening on ${key && cert ? 'https' : 'http'}://localhost:${server.port}`)
