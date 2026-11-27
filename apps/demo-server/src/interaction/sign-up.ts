import { passwordMessages } from '@oidcraft/ui'
import { issuer } from '../op/env'
import { knownAccounts, pendingSecondFactor } from './cookies'
import { type Flow, form, type Kit, parsed, signUp, usernameMessage } from './kit'

/** Self-service sign-up, with a password or a passkey alone, where the host mounts it (FR-I7, FR-I8). */
export const signUpFlow =
  ({ provider, accounts, screens, finish }: Kit): Flow =>
  async ({ request, id, action, view }) => {
    if ((action !== 'register' && action !== 'register-options') || !signUp()) return undefined
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

    const result = await accounts.signUp({ username: values.username, password: body.get('password') ?? '', claims })
    if (result.ok) return finish(request, id, result.accountId, ['pwd'])
    const errors =
      result.reason === 'password'
        ? { password: passwordMessages()[result.problem] }
        : { username: usernameMessage(result.reason === 'taken' ? 'taken' : result.problem) }
    return screens.register(view, { values, errors, passkeys: true, status: 400 })
  }
