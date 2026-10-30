import { PASSWORD_MESSAGES, type ScreenView } from '@oidcraft/ui'
import { OAuthError } from 'oidcraft'
import { type InteractionRequest, oauthFieldError } from 'oidcraft/interaction'
import { optional } from '../op/env'
import { FIRST_PARTY } from '../op/first-party'
import type { Site } from '../op/site'
import { startUpstream, upstreamLabels } from './broker'
import { knownAccounts, pendingSecondFactor } from './cookies'

const seeOther = (location: string, ...cookies: (string | undefined)[]) => {
  const headers = new Headers({ location, 'cache-control': 'no-store' })
  for (const cookie of cookies) if (cookie) headers.append('set-cookie', cookie)
  return new Response(null, { status: 303, headers })
}

/** Sign-up is on unless OIDCRAFT_SIGNUP=off: a deployment that provisions accounts itself leaves it unmounted. */
const signUp = () => optional('OIDCRAFT_SIGNUP') !== 'off'

const offeredUpstreams = (view: InteractionRequest) =>
  upstreamLabels([...new Set([view.upstream?.chosen, ...(view.upstream?.candidates ?? [])].filter(id => id !== undefined))])

const lockedNotice = (until: Date) =>
  `Too many attempts. Try again after ${until.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })}.`

const form = async (request: Request) => new URLSearchParams(await request.text())

/** The screens' routes for one site; built once per site, which is once per realm. */
const build = (site: Site) => {
  const { provider, accounts, screens } = site

  const loginScreen = (view: ScreenView, options: Parameters<typeof screens.login>[1] = {}) =>
    screens.login(view, { upstreams: offeredUpstreams(view), forgot: true, register: signUp(), ...options })

  /**
   * FR-F9 / FR-C16: the acr says what actually happened, because a client that asked for more must
   * not be told it got it. RFC 8176 names the methods.
   */
  const finish = async (request: Request, id: string, accountId: string, amr: string[]) => {
    const { redirectTo, setCookie } = await provider.interactions.complete(id, {
      login: { accountId, acr: amr.includes('mfa') ? 'mfa' : 'pwd', amr }
    })
    return seeOther(redirectTo, setCookie, pendingSecondFactor.clear(), await knownAccounts.add(request, accountId))
  }

  const interactionRoutes = async (request: Request, url: URL) => {
    const [, , id, action] = url.pathname.split('/')
    if (!id) return undefined

    try {
      const found = await provider.interactions.find(id)
      const client = await provider.config.adapter.clients.find(found.clientId)
      const view = { ...found, clientName: client?.clientName }

      if (request.method === 'GET' && !action) {
        // This deployment's own apps are not third parties asking for access; whose consent to ask is the host's call.
        if (view.kind === 'consent' && FIRST_PARTY.includes(view.clientId)) {
          const { redirectTo, setCookie } = await provider.interactions.complete(id, {
            consent: { scopes: view.scopes, authorizationDetails: view.authorizationDetails }
          })
          return seeOther(redirectTo, setCookie)
        }
        if (view.kind === 'consent') return screens.consent(view)
        if (view.kind === 'logout') {
          return screens.logout(view.id, view.clientId ? (client?.clientName ?? view.clientId) : undefined)
        }
        // prompt=select_account asks which identity, not whether to sign in (OIDC Core §3.1.2.1).
        const known = await knownAccounts.get(request)
        return view.prompt.includes('select_account') && known.length
          ? screens.selectAccount(
              view,
              known.map(accountId => ({ accountId, label: accountId }))
            )
          : loginScreen(view)
      }

      if (request.method === 'GET' && action === 'login') return loginScreen(view)

      // Picking an account only fills in the form: being listed is not having proved anything.
      if (request.method === 'POST' && action === 'choose') {
        return loginScreen(view, {
          attempt: { username: (await form(request)).get('username') ?? '', errors: { username: undefined, password: undefined } }
        })
      }

      if (request.method === 'POST' && action === 'login') {
        const body = await form(request)
        const username = body.get('username') ?? ''
        const password = body.get('password') ?? ''
        const errors = { username: oauthFieldError(username), password: oauthFieldError(password) }
        if (errors.username || errors.password) {
          // re-rendered with what was typed: losing it and saying nothing is how the old branch failed
          return loginScreen(view, { attempt: { username, errors }, status: 400 })
        }
        const result = await accounts.authenticate(username, password)
        if (!result.ok) {
          const notice = result.reason === 'locked' ? lockedNotice(result.until) : 'That username and password do not match.'
          return loginScreen(view, {
            attempt: { username, errors: { username: undefined, password: undefined } },
            notice,
            status: result.reason === 'locked' ? 429 : 401
          })
        }
        if (result.secondFactor) {
          return seeOther(`/interaction/${encodeURIComponent(id)}/otp`, await pendingSecondFactor.set(id, result.accountId))
        }
        return finish(request, id, result.accountId, ['pwd'])
      }

      if (action === 'otp' || action === 'recovery') {
        const accountId = await pendingSecondFactor.get(request, id)
        if (!accountId) return loginScreen(view, { notice: 'Sign in with your password first.' })
        const recovery = action === 'recovery'
        if (request.method === 'GET') return screens.otp(view, { recovery })
        const result = await accounts.verifySecondFactor(accountId, (await form(request)).get('code') ?? '')
        if (result.ok) return finish(request, id, accountId, result.method === 'otp' ? ['pwd', 'otp', 'mfa'] : ['pwd', 'mfa'])
        if (result.reason === 'locked') return loginScreen(view, { notice: lockedNotice(result.until), status: 429 })
        return screens.otp(view, { recovery, error: 'That code is not right, or it was already used.', status: 401 })
      }

      if (action === 'register' && signUp()) {
        if (request.method === 'GET') return screens.register(view)
        const body = await form(request)
        const values = { name: body.get('name') ?? '', email: body.get('email') ?? '', username: body.get('username') ?? '' }
        const claims = { ...(values.name && { name: values.name }), ...(values.email && { email: values.email, email_verified: false }) }
        const result = await accounts.register({ username: values.username, password: body.get('password') ?? '', claims })
        if (result.ok) return finish(request, id, result.accountId, ['pwd'])
        const errors =
          result.reason === 'password'
            ? { password: PASSWORD_MESSAGES[result.problem] }
            : result.reason === 'username'
              ? { username: result.problem === 'required' ? 'Choose a username' : 'That username is too long' }
              : { username: 'That username is taken' }
        return screens.register(view, { values, errors, status: 400 })
      }

      if (action === 'forgot') {
        if (request.method === 'GET') return screens.forgot(view)
        const issued = await accounts.reset.issue((await form(request)).get('username') ?? '')
        // Demo delivery. A deployment emails this; it never shows it, or the form hands accounts to anyone.
        if (issued)
          console.log(
            `[demo mail] to ${issued.accountId}: reset your password at ${new URL(`/reset?token=${issued.token}`, provider.config.issuer)}`
          )
        return screens.message('Check your email', 'If that username has an account here, a link to reset its password is on its way.')
      }

      if (request.method === 'POST' && action === 'upstream' && site.brokering) {
        const response = await startUpstream(id, request)
        if (response) return response
      }

      // Declining is not an answer the provider needs: the interaction expires and the session stays.
      if (request.method === 'POST' && action === 'logout') {
        if ((await form(request)).get('decision') !== 'yes') return screens.message('You are still signed in', 'You can close this page.')
        const { redirectTo } = await provider.interactions.complete(id, { logout: true })
        return seeOther(redirectTo)
      }

      if (request.method === 'POST' && action === 'consent') {
        const outcome =
          (await form(request)).get('decision') === 'allow'
            ? { consent: { scopes: view.scopes, authorizationDetails: view.authorizationDetails } }
            : { error: { error: 'access_denied' as const, description: 'the user declined' } }
        const { redirectTo, setCookie } = await provider.interactions.complete(id, outcome)
        return seeOther(redirectTo, setCookie)
      }

      return new Response('Method not allowed', { status: 405 })
    } catch (error) {
      if (!(error instanceof OAuthError)) console.error('[interaction]', error)
      return screens.message('This sign-in expired', 'Start again from the application.', 400)
    }
  }

  /** Where a reset link lands. Outside any interaction, because the one that asked has long expired. */
  const resetRoutes = async (request: Request, url: URL) => {
    if (request.method === 'GET') return screens.reset(url.searchParams.get('token') ?? '')
    const body = await form(request)
    const token = body.get('token') ?? ''
    const result = await accounts.reset.complete(token, body.get('password') ?? '')
    if (result.ok) return screens.message('Password changed', 'Sign in again with your new password, from the application you were using.')
    if (result.reason === 'password') return screens.reset(token, { error: PASSWORD_MESSAGES[result.problem], status: 400 })
    return screens.message('This link no longer works', 'It expired or was already used. Ask for a new one from the sign-in screen.', 400)
  }

  /** The device flow's human half: a person types a code they read on another screen (FR-C7). */
  const deviceRoutes = async (request: Request, url: URL, clientIp: string | undefined) => {
    try {
      return await deviceScreens(request, url, { clientIp })
    } catch (error) {
      // RFC 8628 §5.1: the provider stops answering after too many wrong codes from one address.
      if (error instanceof OAuthError && error.status === 429) {
        return screens.deviceCode('', 'Too many wrong codes. Wait a few minutes and try again.', 429)
      }
      if (error instanceof OAuthError) return screens.deviceCode('', 'That code has expired or was already answered.', 400)
      throw error
    }
  }

  const deviceScreens = async (request: Request, url: URL, context: { clientIp: string | undefined }) => {
    const confirm = async (typed: string) => {
      const found = await provider.device.find(typed, context)
      if (!found) return screens.deviceCode(typed, 'No device is waiting for that code. Check it and try again.', 404)
      const session = await provider.session(request)
      if (!session) return seeOther((await provider.device.signIn(typed, context)).redirectTo)
      return screens.deviceConfirm(typed, found.client.clientName ?? found.client.clientId, found.payload.scopes, session.accountId)
    }

    if (request.method === 'GET' && url.pathname === '/device') {
      const prefilled = url.searchParams.get('user_code') ?? ''
      return prefilled ? confirm(prefilled) : screens.deviceCode()
    }

    if (request.method === 'POST' && url.pathname === '/device') return confirm((await form(request)).get('user_code') ?? '')

    if (request.method === 'POST' && url.pathname === '/device/decide') {
      const body = await form(request)
      const typed = body.get('user_code') ?? ''
      // Approving or refusing on someone's behalf is still doing it as someone (FR-C7).
      const session = await provider.session(request)
      if (!session) return seeOther((await provider.device.signIn(typed, context)).redirectTo)
      try {
        if (body.get('decision') !== 'allow') {
          await provider.device.resolve(typed, { denied: true }, context)
          return screens.deviceDone(false)
        }
        const found = await provider.device.find(typed, context)
        if (!found) return screens.deviceCode(typed, 'That code has expired.', 404)
        await provider.device.resolve(typed, { accountId: session.accountId, sessionId: session.id, scopes: found.payload.scopes }, context)
        return screens.deviceDone(true)
      } catch {
        return screens.deviceCode(typed, 'That code has expired or was already answered.', 400)
      }
    }

    return undefined
  }

  return { interactionRoutes, resetRoutes, deviceRoutes }
}

const built = new WeakMap<Site, ReturnType<typeof build>>()

export const routesFor = (site: Site) => {
  let routes = built.get(site)
  if (!routes) {
    routes = build(site)
    built.set(site, routes)
  }
  return routes
}
