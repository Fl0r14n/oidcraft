import { type Component, createSSRApp, h } from 'vue'
import { renderToString } from 'vue/server-renderer'
import { STYLESHEET } from './assets'
import { BRAND, type Brand, type Theme } from './brand'

const escapeHtml = (value: string) =>
  value.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] as string)

const VARIABLES = { accent: '--oc-accent', accentInk: '--oc-accent-ink', radius: '--oc-radius', font: '--oc-font' } as const

/** A theme value lands inside a style element, so anything that could close it is refused rather than escaped. */
const themeStyle = (theme: Theme) => {
  const declarations = Object.entries(theme)
    .filter((entry): entry is [keyof Theme, string] => typeof entry[1] === 'string' && !/[<>{};]/.test(entry[1]))
    .map(([key, value]) => `${VARIABLES[key]}:${value}`)
  return declarations.length ? `<style>:root{${declarations.join(';')}}</style>` : ''
}

export type RenderOptions = { brand: Brand; theme?: Theme | undefined; status?: number | undefined }

/**
 * Plain server-rendered HTML with no script: every screen is a form that posts. The conformance
 * suite drives these with a browser that runs little JavaScript (NFR-C1).
 */
export const render = async (title: string, component: Component, props: Record<string, unknown>, options: RenderOptions) => {
  const app = createSSRApp({ render: () => h(component, props) })
  app.provide(BRAND, options.brand)
  const body = await renderToString(app)
  return new Response(
    `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark"><title>${escapeHtml(title)} · ${escapeHtml(options.brand.name)}</title>
<link rel="stylesheet" href="${STYLESHEET}">${themeStyle(options.theme ?? {})}</head>
<body>${body}</body></html>`,
    { status: options.status ?? 200, headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' } }
  )
}
