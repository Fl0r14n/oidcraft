import { renderToReadableStream } from 'react-dom/server'
import { createMemoryRouter, RouterProvider } from 'react-router'
import { createApp } from './app'
import { routes } from './routes'

export interface RenderResult {
  body: ReadableStream<Uint8Array>
  head: string
}

/** One render, one instance, disposed once the stream has rendered everything: instances register
 * watchers and count themselves among the live ones, and leaking them breaks global instance
 * resolution. A shell that fails to render rejects, and is disposed at once. */
export const render = async (url: string | URL, locale?: string): Promise<RenderResult> => {
  const { pathname, search } = new URL(url, 'http://localhost')
  const { oauth, i18n, Providers } = createApp(locale)
  try {
    const router = createMemoryRouter(routes, { initialEntries: [`${pathname}${search}`] })
    const body = await renderToReadableStream(
      <Providers>
        <RouterProvider router={router} />
      </Providers>,
      { onError: error => console.error('SSR error:', error) }
    )
    // both outcomes, and nothing re-thrown: a late error is onError's, not an unhandled rejection
    body.allReady.then(
      () => oauth.dispose(),
      () => oauth.dispose()
    )
    // hand the resolved locale to the client: it picks from `navigator.language`, the server from
    // `accept-language`, and when those disagree the first client render contradicts the SSR markup
    return { body, head: `<script>window.__LOCALE__=${JSON.stringify(i18n.resolvedLanguage ?? null)}</script>` }
  } catch (error) {
    oauth.dispose()
    throw error
  }
}
