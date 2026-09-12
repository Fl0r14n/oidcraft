import { provider } from '../provider'
import { consentScreen, html, loginScreen } from './screens'

const seeOther = (location: string, setCookie?: string) =>
  new Response(null, { status: 303, headers: { location, 'cache-control': 'no-store', ...(setCookie && { 'set-cookie': setCookie }) } })

/** Demo only: every password is accepted. A deployment authenticates against its own directory (G-2). */
const authenticate = (username: string) => ({ accountId: username.toLowerCase().trim() })

export const interactionRoutes = async (request: Request, url: URL) => {
  const [, , id, action] = url.pathname.split('/')
  if (!id) return undefined

  try {
    const view = await provider.interactions.find(id)

    if (request.method === 'GET' && !action) {
      return html(view.kind === 'login' ? loginScreen(view) : consentScreen(view))
    }

    if (request.method === 'POST' && action === 'login') {
      const form = new URLSearchParams(await request.text())
      const username = form.get('username')
      if (!username) return html(loginScreen(view), 400)
      const { redirectTo, setCookie } = await provider.interactions.complete(id, { login: authenticate(username) })
      return seeOther(redirectTo, setCookie)
    }

    if (request.method === 'POST' && action === 'consent') {
      const form = new URLSearchParams(await request.text())
      const outcome =
        form.get('decision') === 'allow'
          ? { consent: { scopes: view.scopes } }
          : { error: { error: 'access_denied' as const, description: 'the user declined' } }
      const { redirectTo, setCookie } = await provider.interactions.complete(id, outcome)
      return seeOther(redirectTo, setCookie)
    }

    return new Response('Method not allowed', { status: 405 })
  } catch {
    return html('<h1>This sign-in expired</h1><p class="sub">Start again from the application.</p>', 400)
  }
}
