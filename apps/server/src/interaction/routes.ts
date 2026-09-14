import { provider } from '../provider'
import {
  consentScreen,
  deviceCodeScreen,
  deviceConfirmScreen,
  deviceDoneScreen,
  html,
  loginScreen,
  logoutConfirmScreen,
  selectAccountScreen
} from './screens'

const seeOther = (location: string, setCookie?: string) =>
  new Response(null, { status: 303, headers: { location, 'cache-control': 'no-store', ...(setCookie && { 'set-cookie': setCookie }) } })

/** Demo only: every password is accepted. A deployment authenticates against its own directory (G-2). */
const authenticate = (username: string) => ({ accountId: username.toLowerCase().trim() })

/** Stand-in for a directory lookup, so the account-selection screen has something to show. */
const recentAccounts = [
  { accountId: 'ada', label: 'ada' },
  { accountId: 'grace', label: 'grace' }
]

export const interactionRoutes = async (request: Request, url: URL) => {
  const [, , id, action] = url.pathname.split('/')
  if (!id) return undefined

  try {
    const view = await provider.interactions.find(id)

    if (request.method === 'GET' && !action) {
      if (view.kind === 'consent') return html(consentScreen(view))
      // prompt=select_account asks which identity, not whether to sign in (OIDC Core §3.1.2.1).
      return html(view.prompt.includes('select_account') ? selectAccountScreen(view, recentAccounts) : loginScreen(view))
    }

    if (request.method === 'POST' && action === 'login') {
      const form = new URLSearchParams(await request.text())
      const username = form.get('username')
      if (!username) return html(loginScreen(view), 400)
      const login = authenticate(username)
      // FR-F9 / FR-C16: the client asked for an acr, and claiming to meet it would be a lie the
      // ID token then carries. This demo can only do a password.
      const { redirectTo, setCookie } = await provider.interactions.complete(id, {
        login: { ...login, acr: 'pwd', amr: ['pwd'] }
      })
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

/** The device flow's human half: a person types a code they read on another screen (FR-C7). */
export const deviceRoutes = async (request: Request, url: URL) => {
  if (request.method === 'GET' && url.pathname === '/device') {
    const prefilled = url.searchParams.get('user_code') ?? ''
    if (!prefilled) return html(deviceCodeScreen())
    const found = await provider.device.find(prefilled)
    if (!found) return html(deviceCodeScreen(prefilled, 'That code is not one we are waiting for.'), 404)
    return html(deviceConfirmScreen(prefilled, found.client.clientName ?? found.client.clientId, found.payload.scopes))
  }

  if (request.method === 'POST' && url.pathname === '/device') {
    const form = new URLSearchParams(await request.text())
    const typed = form.get('user_code') ?? ''
    const found = await provider.device.find(typed)
    if (!found) return html(deviceCodeScreen(typed, 'That code is not one we are waiting for.'), 404)
    return html(deviceConfirmScreen(typed, found.client.clientName ?? found.client.clientId, found.payload.scopes))
  }

  if (request.method === 'POST' && url.pathname === '/device/decide') {
    const form = new URLSearchParams(await request.text())
    const typed = form.get('user_code') ?? ''
    const allow = form.get('decision') === 'allow'
    try {
      if (!allow) {
        await provider.device.resolve(typed, { denied: true })
        return html(deviceDoneScreen(false))
      }
      // Demo: a real deployment would require a signed-in session here rather than inventing one.
      const found = await provider.device.find(typed)
      if (!found) return html(deviceCodeScreen(typed, 'That code has expired.'), 404)
      const session = {
        id: crypto.randomUUID(),
        accountId: 'ada',
        authTime: new Date(),
        acr: 'pwd',
        clients: [found.artifact.clientId],
        expiresAt: new Date(Date.now() + 3_600_000)
      }
      await provider.config.adapter.sessions.upsert(session)
      await provider.device.resolve(typed, { accountId: session.accountId, sessionId: session.id, scopes: found.payload.scopes })
      return html(deviceDoneScreen(true))
    } catch {
      return html(deviceCodeScreen(typed, 'That code has expired or was already answered.'), 400)
    }
  }

  return undefined
}

export const logoutRoutes = async (request: Request, url: URL) => {
  if (request.method === 'GET' && url.pathname === '/interaction/logout') {
    return html(logoutConfirmScreen(url.searchParams.get('client_name') ?? undefined, url.searchParams.get('return_to') ?? undefined))
  }
  return undefined
}
