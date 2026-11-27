import { type Component, createSSRApp, h } from 'vue'
import { renderToString } from 'vue/server-renderer'
import { BRAND, type Brand, type Theme } from './brand'

const escapeHtml = (value: string) =>
  value.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] as string)

const VARIABLES = { accent: '--oc-accent', accentInk: '--oc-accent-ink', radius: '--oc-radius', font: '--oc-font' } as const

/** A theme value lands inside a style element, so anything that could close it is refused rather than escaped. */
const themeCss = (theme: Theme) => {
  const declarations = Object.entries(theme)
    .filter((entry): entry is [keyof Theme, string] => typeof entry[1] === 'string' && !/[<>{};]/.test(entry[1]))
    .map(([key, value]) => `${VARIABLES[key]}:${value}`)
  return declarations.length ? `:root{${declarations.join(';')}}` : ''
}

const sha256 = async (text: string) =>
  btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)))))

/** `'self'`, and the origin of each asset served from elsewhere. */
const sources = (...urls: (string | undefined)[]) => {
  const origins = urls.filter((url): url is string => !!url && URL.canParse(url)).map(url => new URL(url).origin)
  return ["'self'", ...new Set(origins)].join(' ')
}

/**
 * D-7, RFC 9700 §4.16: a sign-in screen framed by another site is a clickjacking target, so no site may frame one. The
 * one inline element, the theme's style, is allowed by its hash. No form-action: browsers apply it to the redirects a
 * post leads to, and a sign-in ends in one to the client's redirect URI or to an upstream.
 */
const securityHeaders = async (options: RenderOptions, css: string) => ({
  'content-security-policy': [
    "default-src 'none'",
    `script-src ${sources(options.script)}`,
    `style-src ${sources(options.stylesheet)}${css ? ` 'sha256-${await sha256(css)}'` : ''}`,
    `img-src 'self' https: data:`,
    `font-src ${sources(options.stylesheet)}`,
    "connect-src 'self'",
    "base-uri 'none'",
    "frame-ancestors 'none'"
  ].join('; '),
  'x-frame-options': 'DENY',
  'x-content-type-options': 'nosniff',
  // A reset or email sign-in screen carries its token in the URL, which no request elsewhere repeats. Not no-referrer: a
  // post would then carry `Origin: null`, and the email sign-in accepts its post only from this origin (FR-I9.5).
  'referrer-policy': 'same-origin'
})

export type RenderOptions = {
  brand: Brand
  theme?: Theme | undefined
  status?: number | undefined
  stylesheet: string
  script?: string | undefined
}

/** Plain server-rendered HTML, every screen a form that posts: the conformance suite's browser runs little (NFR-C1). Only passkeys add a script (FR-I8). */
export const render = async (title: string, component: Component, props: Record<string, unknown>, options: RenderOptions) => {
  const app = createSSRApp({ render: () => h(component, props) })
  app.provide(BRAND, options.brand)
  const body = await renderToString(app)
  const css = themeCss(options.theme ?? {})
  return new Response(
    `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark"><title>${escapeHtml(title)} · ${escapeHtml(options.brand.name)}</title>
<link rel="stylesheet" href="${escapeHtml(options.stylesheet)}">${css ? `<style>${css}</style>` : ''}${
      options.script ? `<script type="module" src="${escapeHtml(options.script)}"></script>` : ''
    }</head>
<body>${body}</body></html>`,
    {
      status: options.status ?? 200,
      headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', ...(await securityHeaders(options, css)) }
    }
  )
}
