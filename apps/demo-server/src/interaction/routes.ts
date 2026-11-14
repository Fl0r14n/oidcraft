import { OAuthError } from '@oidcraft/provider'
import { type InteractionRequest, oauthFieldError } from '@oidcraft/provider/interaction'
import { PASSWORD_MESSAGES, type ScreenView } from '@oidcraft/ui'
import { sendRecoveryLink } from '../op/accounts'
import { issuer, optional } from '../op/env'
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

const parsed = (text: string | null) => {
  try {
    return JSON.parse(text ?? '')
  } catch {
    return undefined
  }
}

const usernameMessage = (problem: 'required' | 'tooLong' | 'taken') =>
  problem === 'required' ? 'Choose a username' : problem === 'tooLong' ? 'That username is too long' : 'That username is taken'

const build = (site: Site) => {
  const { provider, accounts, screens } = site

  const loginScreen = (view: ScreenView, options: Parameters<typeof screens.login>[1] = {}) =>
    screens.login(view, { upstreams: offeredUpstreams(view), forgot: true, register: signUp(), passkeys: true, recover: true, ...options })

  const secondStep = async (view: ScreenView, accountId: string, options: Parameters<typeof screens.otp>[1] = {}) =>
    screens.otp(view, { passkeys: (await accounts.passkeys.list(accountId)).length > 0, ...options })

  /** The acr says what actually happened: a client that asked for more must not be told it got it (FR-F9, FR-C16, RFC 8176). */
  const finish = async (request: Request, id: string, accountId: string, amr: string[], acr = amr.includes('mfa') ? 'mfa' : 'pwd') => {
    const { redirectTo, setCookie } = await provider.interactions.complete(
      id,
      { login: { accountId, acr, amr } },
      request.headers.get('cookie')
    )
    return seeOther(redirectTo, setCookie, pendingSecondFactor.clear(), await knownAccounts.add(request, accountId))
  }

  const interactionRoutes = async (request: Request, url: URL, clientIp: string | undefined) => {
    const [, , id, action] = url.pathname.split('/')
    if (!id) return undefined

    try {
      const found = await provider.interactions.find(id)
      const client = await provider.config.adapter.clients.find(found.clientId)
      const view = { ...found, clientName: client?.clientName }

      if (request.method === 'GET' && !action) {
        // This deployment's own apps are not third parties asking for access; whose consent to ask is the host's call.
        if (view.kind === 'consent' && FIRST_PARTY.includes(view.clientId)) {
          const { redirectTo, setCookie } = await provider.interactions.complete(
            id,
            {
              consent: { scopes: view.scopes, claims: view.claims, authorizationDetails: view.authorizationDetails }
            },
            request.headers.get('cookie')
          )
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
        if (body.get('decision') === 'cancel') {
          const { redirectTo, setCookie } = await provider.interactions.complete(
            id,
            {
              error: { error: 'access_denied', description: 'the user cancelled the sign-in' }
            },
            request.headers.get('cookie')
          )
          return seeOther(redirectTo, setCookie)
        }
        const username = body.get('username') ?? ''
        const password = body.get('password') ?? ''
        const errors = { username: oauthFieldError(username), password: oauthFieldError(password) }
        if (errors.username || errors.password) {
          return loginScreen(view, { attempt: { username, errors }, status: 400 })
        }
        const result = await accounts.authenticate(username, password, { clientIp })
        if (!result.ok) {
          // G-9: a lock answered differently from a wrong password would confirm the username exists.
          return loginScreen(view, {
            attempt: { username, errors: { username: undefined, password: undefined } },
            notice: 'That username and password do not match.',
            status: 401
          })
        }
        if (result.secondFactor) {
          return seeOther(`/interaction/${encodeURIComponent(id)}/otp`, await pendingSecondFactor.set(id, result.accountId))
        }
        return await finish(request, id, result.accountId, ['pwd'])
      }

      if (action === 'otp' || action === 'recovery') {
        const accountId = await pendingSecondFactor.get(request, id)
        if (!accountId) return loginScreen(view, { notice: 'Sign in with your password first.' })
        const recovery = action === 'recovery'
        if (request.method === 'GET') return secondStep(view, accountId, { recovery })
        const result = await accounts.verifySecondFactor(accountId, (await form(request)).get('code') ?? '', { clientIp })
        if (result.ok) return await finish(request, id, accountId, result.method === 'otp' ? ['pwd', 'otp', 'mfa'] : ['pwd', 'mfa'])
        if (result.reason === 'locked') return loginScreen(view, { notice: lockedNotice(result.until), status: 429 })
        return secondStep(view, accountId, { recovery, error: 'That code is not right, or it was already used.', status: 401 })
      }

      // FR-I8: a sign-in of its own, or the second step after a password, when that account has a passkey.
      if (request.method === 'POST' && (action === 'passkey-options' || action === 'passkey')) {
        const body = await form(request)
        const second = body.get('step') === 'second'
        const pending = second ? await pendingSecondFactor.get(request, id) : undefined
        if (second && !pending) return loginScreen(view, { notice: 'Sign in with your password first.', status: 401 })
        if (action === 'passkey-options') {
          return Response.json(await accounts.passkeys.authenticationOptions(id, pending ? { accountId: pending } : {}), {
            headers: { 'cache-control': 'no-store' }
          })
        }
        const result = await accounts.passkeys.authenticate(id, parsed(body.get('credential')))
        if (result.ok && (!pending || result.accountId === pending)) {
          return await finish(request, id, result.accountId, pending ? ['pwd', 'hwk', 'user', 'mfa'] : ['hwk', 'user'], 'mfa')
        }
        if (!result.ok && result.reason === 'counter') console.warn(`[interaction] a passkey's counter went backwards: it may be cloned`)
        const notice = 'That passkey could not sign you in.'
        return pending ? secondStep(view, pending, { error: notice, status: 401 }) : loginScreen(view, { notice, status: 401 })
      }

      if ((action === 'register' || action === 'register-options') && signUp()) {
        if (request.method === 'GET') return screens.register(view, { passkeys: true })
        const body = await form(request)
        const values = { name: body.get('name') ?? '', email: body.get('email') ?? '', username: body.get('username') ?? '' }
        const claims = { ...(values.name && { name: values.name }), ...(values.email && { email: values.email, email_verified: false }) }

        // FR-I8: an account with a passkey and no password; the script asks for options with the form's fields, then posts.
        if (action === 'register-options') {
          const asked = await accounts.passkeys.signUpOptions(id, { username: values.username, claims })
          if (asked.ok) return Response.json(asked.options, { headers: { 'cache-control': 'no-store' } })
          const problem = asked.reason === 'taken' ? 'taken' : asked.problem
          return Response.json({ error: 'invalid_username', error_description: `${usernameMessage(problem)}.` }, { status: 400 })
        }
        if (body.get('credential')) {
          const created = await accounts.passkeys.signUp(id, parsed(body.get('credential')), 'Passkey')
          if (created.ok) {
            const { redirectTo, setCookie } = await provider.interactions.complete(
              id,
              { login: { accountId: created.accountId, acr: 'mfa', amr: ['hwk', 'user'] } },
              request.headers.get('cookie')
            )
            // The account app manages the main issuer's accounts only, not a realm's.
            const accountUrl = provider.config.issuer === issuer() ? new URL('/account', issuer()).toString() : undefined
            const response = await screens.recoveryCodes(created.recoveryCodes, redirectTo, accountUrl ? { accountUrl } : {})
            for (const cookie of [setCookie, pendingSecondFactor.clear(), await knownAccounts.add(request, created.accountId)]) {
              if (cookie) response.headers.append('set-cookie', cookie)
            }
            return response
          }
          const notice = created.reason === 'taken' ? undefined : 'No account was created: the passkey could not be checked. Try again.'
          const errors = created.reason === 'taken' ? { username: usernameMessage('taken') } : {}
          return screens.register(view, { values, errors, notice, passkeys: true, status: 400 })
        }

        const result = await accounts.register({ username: values.username, password: body.get('password') ?? '', claims })
        if (result.ok) return await finish(request, id, result.accountId, ['pwd'])
        const errors =
          result.reason === 'password'
            ? { password: PASSWORD_MESSAGES[result.problem] }
            : { username: usernameMessage(result.reason === 'taken' ? 'taken' : result.problem) }
        return screens.register(view, { values, errors, passkeys: true, status: 400 })
      }

      if (action === 'forgot') {
        if (request.method === 'GET') return screens.forgot(view)
        const issued = await accounts.reset.issue((await form(request)).get('username') ?? '')
        if (issued) sendRecoveryLink(issued.accountId, issued.token, provider.config.issuer)
        return screens.message('Check your email', 'If that username has an account here, a link to get back in is on its way.')
      }

      // FR-I8: a recovery code in place of a lost passkey, for an account with no password. It signs no one in: it leads to
      // the reset screen, which adds a passkey or sets a password and ends what the old credentials opened.
      if (action === 'recover') {
        if (request.method === 'GET') return screens.recover(view, { forgot: true })
        const body = await form(request)
        const username = body.get('username') ?? ''
        const recovered = await accounts.recover(username, body.get('code') ?? '', { clientIp })
        if (recovered.ok) return screens.reset(recovered.token, { passkeys: true })
        // G-9: a lock answered differently from a wrong code would confirm the username exists.
        return screens.recover(view, {
          username,
          forgot: true,
          error: 'That username and recovery code do not match, or the code was already used.',
          status: 401
        })
      }

      if (request.method === 'POST' && action === 'upstream' && site.brokering) {
        const response = await startUpstream(id, request)
        if (response) return response
      }

      // Declining is not an answer the provider needs: the interaction expires and the session stays.
      if (request.method === 'POST' && action === 'logout') {
        if ((await form(request)).get('decision') !== 'yes') return screens.message('You are still signed in', 'You can close this page.')
        const { redirectTo } = await provider.interactions.complete(id, { logout: true }, request.headers.get('cookie'))
        return seeOther(redirectTo)
      }

      if (request.method === 'POST' && action === 'consent') {
        const outcome =
          (await form(request)).get('decision') === 'allow'
            ? { consent: { scopes: view.scopes, claims: view.claims, authorizationDetails: view.authorizationDetails } }
            : { error: { error: 'access_denied' as const, description: 'the user declined' } }
        const { redirectTo, setCookie } = await provider.interactions.complete(id, outcome, request.headers.get('cookie'))
        return seeOther(redirectTo, setCookie)
      }

      return new Response('Method not allowed', { status: 405 })
    } catch (error) {
      if (!(error instanceof OAuthError)) console.error('[interaction]', error)
      return screens.message('This sign-in expired', 'Start again from the application.', 400)
    }
  }

  /** Where a reset link lands. Outside any interaction, because the one that asked has long expired. */
  const resetRoutes = async (request: Request, url: URL, clientIp: string | undefined) => {
    if (request.method === 'GET') return screens.reset(url.searchParams.get('token') ?? '', { passkeys: true })
    const body = await form(request)
    const token = body.get('token') ?? ''
    const expired = () =>
      screens.message('This link no longer works', 'It expired or was already used. Ask for a new one from the sign-in screen.', 400)

    if (url.searchParams.get('step') === 'passkey-options') {
      const options = await accounts.reset.passkeyOptions(token)
      return options
        ? Response.json(options, { headers: { 'cache-control': 'no-store' } })
        : Response.json({ error: 'invalid_token', error_description: 'This link expired or was already used.' }, { status: 400 })
    }
    if (body.get('credential')) {
      const added = await accounts.reset.completeWithPasskey(token, parsed(body.get('credential')), 'Passkey', { clientIp })
      if (added.ok) return screens.message('Passkey added', 'Sign in again with it, from the application you were using.')
      const error =
        added.reason === 'taken'
          ? 'That passkey is already registered.'
          : 'That passkey could not be added. Try again, or ask for a new link if this one has expired.'
      return screens.reset(token, { error, passkeys: true, status: 400 })
    }

    const result = await accounts.reset.complete(token, body.get('password') ?? '', { clientIp })
    if (result.ok) return screens.message('Password changed', 'Sign in again with your new password, from the application you were using.')
    if (result.reason === 'password') {
      return screens.reset(token, { error: PASSWORD_MESSAGES[result.problem], passkeys: true, status: 400 })
    }
    return expired()
  }

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
    // The sign-in it starts is bound to this browser, by the cookie that goes with the redirect (FR-I2).
    const signIn = async (typed: string) => {
      const { redirectTo, setCookie } = await provider.device.signIn(typed, { ...context, cookie: request.headers.get('cookie') })
      return seeOther(redirectTo, setCookie)
    }

    const confirm = async (typed: string) => {
      const found = await provider.device.find(typed, context)
      if (!found) return screens.deviceCode(typed, 'No device is waiting for that code. Check it and try again.', 404)
      const session = await provider.session(request)
      if (!session) return signIn(typed)
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
      if (!session) return signIn(typed)
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
