import { passwordMessages } from '@oidcraft/ui'
import { sendRecoveryLink } from '../op/accounts'
import { resumeAfterReset } from './cookies'
import { type Flow, form, type Kit, parsed, seeOther, withCookie } from './kit'

/** Getting back in: a reset link asked for at the sign-in, a recovery code for a lost passkey, and where a link lands (FR-I7, FR-I8). */
export const recoveryFlow = ({ provider, accounts, screens }: Kit) => {
  const interaction: Flow = async ({ request, id, action, view, clientIp }) => {
    if (action === 'forgot') {
      if (request.method === 'GET') return screens.forgot(view)
      const issued = await accounts.reset.issue((await form(request)).get('username') ?? '')
      if (issued) sendRecoveryLink(issued.accountId, issued.token, provider.config.issuer)
      // Set whether or not the username exists, so the response does not tell them apart (G-9).
      return withCookie(
        screens.message('Check your email', 'If that username has an account here, a link to get back in is on its way.'),
        await resumeAfterReset.set(id)
      )
    }

    // FR-I8: a recovery code in place of a lost passkey, for an account with no password. It signs no one in: it leads to
    // the reset screen, which adds a passkey or sets a password and ends what the old credentials opened.
    if (action === 'recover') {
      if (request.method === 'GET') return screens.recover(view, { forgot: true })
      const body = await form(request)
      const username = body.get('username') ?? ''
      const recovered = await accounts.recover(username, body.get('code') ?? '', { clientIp })
      if (recovered.ok) return withCookie(screens.reset(recovered.token, { passkeys: true }), await resumeAfterReset.set(id))
      // G-9: a lock answered differently from a wrong code would confirm the username exists.
      return screens.recover(view, {
        username,
        forgot: true,
        error: 'That username and recovery code do not match, or the code was already used.',
        status: 401
      })
    }
    return undefined
  }

  /** Back to the sign-in the reset was asked from when this browser asked and it is still open; otherwise only a message. */
  const resumed = async (request: Request, changed: 'password' | 'passkey', title: string, text: string) => {
    const id = await resumeAfterReset.get(request)
    const open =
      id &&
      (await provider.interactions.find(id).then(
        found => found.kind === 'login',
        () => false
      ))
    return open
      ? seeOther(`/interaction/${encodeURIComponent(id)}/login?changed=${changed}`, resumeAfterReset.clear())
      : withCookie(screens.message(title, text), resumeAfterReset.clear())
  }

  /** Where a reset link lands. Outside any interaction, because the one that asked may have expired. */
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
      if (added.ok) {
        // FR-I8: a recovery ends what the lost passkey opened, not the passkey; only its owner knows which one is gone.
        return resumed(
          request,
          'passkey',
          'Passkey added',
          'Sign in again with it, from the application you were using, then remove the passkey you lost from your account: it still signs in.'
        )
      }
      const error =
        added.reason === 'taken'
          ? 'That passkey is already registered.'
          : 'That passkey could not be added. Try again, or ask for a new link if this one has expired.'
      return screens.reset(token, { error, passkeys: true, status: 400 })
    }

    const result = await accounts.reset.complete(token, body.get('password') ?? '', { clientIp })
    if (result.ok)
      return resumed(request, 'password', 'Password changed', 'Sign in again with your new password, from the application you were using.')
    if (result.reason === 'password') {
      return screens.reset(token, { error: passwordMessages()[result.problem], passkeys: true, status: 400 })
    }
    return expired()
  }

  return { interaction, resetRoutes }
}
