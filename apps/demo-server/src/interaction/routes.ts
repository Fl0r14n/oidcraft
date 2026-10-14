import { OAuthError } from 'oidcraft'
import { type InteractionRequest, oauthFieldError } from 'oidcraft/interaction'
import { provider } from '../op/provider'
import { startUpstream, upstreamLabels } from './federation'
import { screens } from './screens'

const seeOther = (location: string, setCookie?: string) =>
  new Response(null, { status: 303, headers: { location, 'cache-control': 'no-store', ...(setCookie && { 'set-cookie': setCookie }) } })

/** Demo only: every password is accepted. A deployment authenticates through its `AccountStore` (FR-I7). */
const authenticate = (username: string) => ({ accountId: username.toLowerCase().trim() })

/** Stand-in for a directory lookup, so the account-selection screen has something to show. */
const recentAccounts = [
  { accountId: 'ada', label: 'ada' },
  { accountId: 'grace', label: 'grace' }
]

const offeredUpstreams = (view: InteractionRequest) =>
  upstreamLabels([...new Set([view.upstream?.chosen, ...(view.upstream?.candidates ?? [])].filter(id => id !== undefined))])

export const interactionRoutes = async (request: Request, url: URL) => {
  const [, , id, action] = url.pathname.split('/')
  if (!id) return undefined

  try {
    const found = await provider.interactions.find(id)
    const client = await provider.config.adapter.clients.find(found.clientId)
    const view = { ...found, clientName: client?.clientName }

    if (request.method === 'GET' && !action) {
      if (view.kind === 'consent') return screens.consent(view)
      if (view.kind === 'logout') {
        return screens.logout(view.id, view.clientId ? (client?.clientName ?? view.clientId) : undefined)
      }
      // prompt=select_account asks which identity, not whether to sign in (OIDC Core §3.1.2.1).
      return view.prompt.includes('select_account')
        ? screens.selectAccount(view, recentAccounts)
        : screens.login(view, undefined, offeredUpstreams(view))
    }

    if (request.method === 'POST' && action === 'login') {
      const form = new URLSearchParams(await request.text())
      const username = form.get('username')
      // The account picker posts a username and no password field at all, so the password is only
      // validated when the form that sent it actually had one (see selectAccountScreen).
      const errors = {
        username: oauthFieldError(username),
        password: form.has('password') ? oauthFieldError(form.get('password')) : undefined
      }
      if (errors.username || errors.password) {
        // re-rendered with what was typed: losing it and saying nothing is how the old branch failed
        return screens.login(view, { username: username ?? '', errors }, offeredUpstreams(view), 400)
      }
      const login = authenticate(username as string)
      // FR-F9 / FR-C16: the client asked for an acr, and claiming to meet it would be a lie the
      // ID token then carries. This demo can only do a password.
      const { redirectTo, setCookie } = await provider.interactions.complete(id, {
        login: { ...login, acr: 'pwd', amr: ['pwd'] }
      })
      return seeOther(redirectTo, setCookie)
    }

    if (request.method === 'POST' && action === 'upstream') {
      const response = await startUpstream(id, request)
      if (response) return response
    }

    // Declining is not an answer the provider needs: the interaction expires and the session stays.
    if (request.method === 'POST' && action === 'logout') {
      const form = new URLSearchParams(await request.text())
      if (form.get('decision') !== 'yes') return screens.message('You are still signed in', 'You can close this page.')
      const { redirectTo } = await provider.interactions.complete(id, { logout: true })
      return seeOther(redirectTo)
    }

    if (request.method === 'POST' && action === 'consent') {
      const form = new URLSearchParams(await request.text())
      const outcome =
        form.get('decision') === 'allow'
          ? { consent: { scopes: view.scopes, authorizationDetails: view.authorizationDetails } }
          : { error: { error: 'access_denied' as const, description: 'the user declined' } }
      const { redirectTo, setCookie } = await provider.interactions.complete(id, outcome)
      return seeOther(redirectTo, setCookie)
    }

    return new Response('Method not allowed', { status: 405 })
  } catch {
    return screens.message('This sign-in expired', 'Start again from the application.', 400)
  }
}

/** The device flow's human half: a person types a code they read on another screen (FR-C7). */
export const deviceRoutes = async (request: Request, url: URL, clientIp: string | undefined) => {
  try {
    return await deviceScreens(request, url, { clientIp })
  } catch (error) {
    // RFC 8628 §5.1: the provider stops answering after too many wrong codes from one address.
    if (error instanceof OAuthError && error.status === 429) {
      return screens.deviceCode('', 'Too many wrong codes. Wait a few minutes and try again.', 429)
    }
    throw error
  }
}

const deviceScreens = async (request: Request, url: URL, context: { clientIp: string | undefined }) => {
  if (request.method === 'GET' && url.pathname === '/device') {
    const prefilled = url.searchParams.get('user_code') ?? ''
    if (!prefilled) return screens.deviceCode()
    const found = await provider.device.find(prefilled, context)
    if (!found) return screens.deviceCode(prefilled, 'No device is waiting for that code. Check it and try again.', 404)
    return screens.deviceConfirm(prefilled, found.client.clientName ?? found.client.clientId, found.payload.scopes)
  }

  if (request.method === 'POST' && url.pathname === '/device') {
    const form = new URLSearchParams(await request.text())
    const typed = form.get('user_code') ?? ''
    const found = await provider.device.find(typed, context)
    if (!found) return screens.deviceCode(typed, 'No device is waiting for that code. Check it and try again.', 404)
    return screens.deviceConfirm(typed, found.client.clientName ?? found.client.clientId, found.payload.scopes)
  }

  if (request.method === 'POST' && url.pathname === '/device/decide') {
    const form = new URLSearchParams(await request.text())
    const typed = form.get('user_code') ?? ''
    const allow = form.get('decision') === 'allow'
    try {
      if (!allow) {
        await provider.device.resolve(typed, { denied: true }, context)
        return screens.deviceDone(false)
      }
      // Demo: a real deployment would require a signed-in session here rather than inventing one.
      const found = await provider.device.find(typed, context)
      if (!found) return screens.deviceCode(typed, 'That code has expired.', 404)
      const session = {
        id: crypto.randomUUID(),
        accountId: 'ada',
        authTime: new Date(),
        acr: 'pwd',
        clients: [found.artifact.clientId],
        expiresAt: new Date(Date.now() + 3_600_000)
      }
      await provider.config.adapter.sessions.upsert(session)
      await provider.device.resolve(typed, { accountId: session.accountId, sessionId: session.id, scopes: found.payload.scopes }, context)
      return screens.deviceDone(true)
    } catch {
      return screens.deviceCode(typed, 'That code has expired or was already answered.', 400)
    }
  }

  return undefined
}
