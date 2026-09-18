import { GlobalRegistrator } from '@happy-dom/global-registrator'

/**
 * `bun test` runs in a bare runtime; the hooks and `@testing-library/react` need a DOM. Imported by
 * each React test file rather than preloaded, because the root `bunfig.toml` preload is global and
 * this registration has a sharp edge for everything else in the process.
 *
 * happy-dom installs its own `fetch`, routed through `node:http`. Under Bun that shim mis-parses
 * responses from a `Bun.serve` origin — `HPE_UNEXPECTED_CONTENT_LENGTH` — and this process also runs
 * `broker.live.test.ts`, which brokers against exactly such a server. Bun's native fetch is both
 * spec-compliant and what the library actually gets at runtime, so it goes back. Nothing here wants
 * happy-dom's fetch: this is for the DOM, not the network.
 *
 * The body types go back with it. A happy-dom `FormData` handed to Bun's fetch is not the one it
 * knows, so it is never serialized as multipart and the request goes out with no Content-Type at all
 * — which looks exactly like a library bug and is not one.
 *
 * `AbortController` and `AbortSignal` go back for the same reason, and that pair is not optional
 * here: `jose` gives its JWKS request a timeout signal, and Bun's fetch rejects a signal built by
 * happy-dom's constructor with "signal is not of type AbortSignal". Measured 2026-09-18 — without it
 * every JWS verification that has to fetch a key set fails, and it fails as "invalid token", which
 * points at everything except the cause.
 */
const native = {
  fetch: globalThis.fetch,
  Request: globalThis.Request,
  Response: globalThis.Response,
  Headers: globalThis.Headers,
  FormData: globalThis.FormData,
  Blob: globalThis.Blob,
  AbortController: globalThis.AbortController,
  AbortSignal: globalThis.AbortSignal
}

if (typeof (globalThis as { document?: unknown }).document === 'undefined') {
  GlobalRegistrator.register()
  for (const [name, value] of Object.entries(native)) {
    Object.defineProperty(globalThis, name, { value, configurable: true, writable: true })
  }
}
