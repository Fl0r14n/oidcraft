import { type Component, createSSRApp, h } from 'vue'
import { renderToString } from 'vue/server-renderer'
import { STYLESHEET } from '../ui/assets'

const escapeHtml = (value: string) =>
  value.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] as string)

/**
 * Plain server-rendered HTML with no script: every screen is a form that posts. The conformance
 * suite drives these with a browser that runs little JavaScript (NFR-C1).
 */
export const render = async (title: string, component: Component, props: Record<string, unknown>, status = 200) => {
  const body = await renderToString(createSSRApp({ render: () => h(component, props) }))
  return new Response(
    `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark"><title>${escapeHtml(title)}</title><link rel="stylesheet" href="${STYLESHEET}"></head>
<body>${body}</body></html>`,
    { status, headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' } }
  )
}
