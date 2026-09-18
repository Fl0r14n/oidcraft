import { renderToString } from 'react-dom/server'
import { createMemoryRouter, RouterProvider } from 'react-router'
import { createApp } from './app'
import { routes } from './routes'

export interface RenderResult {
  body: string
  head: string
}

/** One render, one instance. The `finally` is the point: instances register watchers and count
 * themselves among the live ones, and leaking them breaks global instance resolution. */
export const render = async (url: string | URL, locale?: string): Promise<RenderResult> => {
  const { pathname, search } = new URL(url, 'http://localhost')
  const { oauth, i18n, Providers } = createApp(locale)
  try {
    const router = createMemoryRouter(routes, { initialEntries: [`${pathname}${search}`] })
    const body = renderToString(
      <Providers>
        <RouterProvider router={router} />
      </Providers>
    )
    // hand the resolved locale to the client: it picks from `navigator.language`, the server from
    // `accept-language`, and when those disagree the first client render contradicts the SSR markup
    return { body, head: `<script>window.__LOCALE__=${JSON.stringify(i18n.resolvedLanguage ?? null)}</script>` }
  } finally {
    oauth.dispose()
  }
}
