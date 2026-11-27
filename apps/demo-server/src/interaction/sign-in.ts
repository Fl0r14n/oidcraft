import { oauthFieldError } from '@oidcraft/provider/interaction'
import { credentialsOf } from '../op/accounts'
import { FIRST_PARTY } from '../op/first-party'
import { startUpstream } from './broker'
import { knownAccounts, pendingSecondFactor } from './cookies'
import { afterReset, type Flow, form, type Kit, lockedNotice, parsed, seeOther } from './kit'

/** Signing in at an interaction: the screen, a password, the second step, a passkey, an upstream, and what follows it. */
export const signInFlow =
  ({ site, provider, accounts, screens, loginScreen, secondStep, finish }: Kit): Flow =>
  async ({ request, url, id, action, view, client, clientIp }) => {
    if (request.method === 'GET' && !action) {
      // This deployment's own apps are not third parties asking for access; whose consent to ask is the host's call.
      if (view.kind === 'consent' && FIRST_PARTY.includes(view.clientId)) {
        const { redirectTo, setCookie } = await provider.interactions.complete(
          id,
          { consent: { scopes: view.scopes, claims: view.claims, authorizationDetails: view.authorizationDetails } },
          request.headers.get('cookie')
        )
        return seeOther(redirectTo, setCookie)
      }
      if (view.kind === 'consent') return screens.consent(view)
      if (view.kind === 'logout') return screens.logout(view.id, view.clientId ? (client?.clientName ?? view.clientId) : undefined)
      // prompt=select_account asks which identity, not whether to sign in (OIDC Core §3.1.2.1).
      const known = await knownAccounts.get(request)
      if (!view.prompt.includes('select_account') || !known.length) return loginScreen(view)
      // Account ids are random (D-1); a person picks by the username they sign in with.
      const credentials = credentialsOf(provider)
      const labelled = await Promise.all(
        known.map(async accountId => ({ accountId, label: (await credentials?.find(accountId))?.username ?? accountId }))
      )
      return screens.selectAccount(view, labelled)
    }

    if (request.method === 'GET' && action === 'login') return loginScreen(view, { notice: afterReset(url.searchParams.get('changed')) })

    // Picking an account only fills in the form: being listed is not having proved anything.
    if (request.method === 'POST' && action === 'choose') {
      const chosen = (await form(request)).get('username') ?? ''
      const username = (await credentialsOf(provider)?.find(chosen))?.username ?? chosen
      return loginScreen(view, { attempt: { username, errors: { username: undefined, password: undefined } } })
    }

    if (request.method === 'POST' && action === 'login') {
      const body = await form(request)
      if (body.get('decision') === 'cancel') {
        const { redirectTo, setCookie } = await provider.interactions.complete(
          id,
          { error: { error: 'access_denied', description: 'the user cancelled the sign-in' } },
          request.headers.get('cookie')
        )
        return seeOther(redirectTo, setCookie)
      }
      const username = body.get('username') ?? ''
      const password = body.get('password') ?? ''
      const errors = { username: oauthFieldError(username), password: oauthFieldError(password) }
      if (errors.username || errors.password) return loginScreen(view, { attempt: { username, errors }, status: 400 })
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
      return finish(request, id, result.accountId, ['pwd'])
    }

    if (action === 'otp' || action === 'recovery') {
      const accountId = await pendingSecondFactor.get(request, id)
      if (!accountId) return loginScreen(view, { notice: 'Sign in with your password first.' })
      const recovery = action === 'recovery'
      if (request.method === 'GET') return secondStep(view, accountId, { recovery })
      const result = await accounts.verifySecondFactor(accountId, (await form(request)).get('code') ?? '', { clientIp })
      const first = (await pendingSecondFactor.byEmail(request, id)) ? 'email' : 'pwd'
      if (result.ok) return finish(request, id, accountId, result.method === 'otp' ? [first, 'otp', 'mfa'] : [first, 'mfa'])
      if (result.reason === 'locked') return loginScreen(view, { notice: lockedNotice(result.lock), status: 429 })
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
        const first = (await pendingSecondFactor.byEmail(request, id)) ? 'email' : 'pwd'
        return finish(request, id, result.accountId, pending ? [first, 'hwk', 'user', 'mfa'] : ['hwk', 'user'], 'mfa')
      }
      if (!result.ok && result.reason === 'counter') console.warn(`[interaction] a passkey's counter went backwards: it may be cloned`)
      const notice = 'That passkey could not sign you in.'
      return pending ? secondStep(view, pending, { error: notice, status: 401 }) : loginScreen(view, { notice, status: 401 })
    }

    if (request.method === 'POST' && action === 'upstream' && site.brokering) return startUpstream(id, request)

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

    return undefined
  }
