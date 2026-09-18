import { StrictMode } from 'react'
import { createRoot, hydrateRoot } from 'react-dom/client'
import { createBrowserRouter, RouterProvider } from 'react-router'
import { createApp } from './app'
import { routes } from './routes'

const { Providers } = createApp((globalThis as { __LOCALE__?: string }).__LOCALE__)
const router = createBrowserRouter(routes)

const app = (
  <StrictMode>
    <Providers>
      <RouterProvider router={router} />
    </Providers>
  </StrictMode>
)

const container = document.getElementById('app')
if (!container) {
  throw new Error('missing #app — index.html and the SSR template must agree on the mount point')
}

if (container.firstElementChild) {
  hydrateRoot(container, app)
} else {
  createRoot(container).render(app)
}
