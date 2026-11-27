import { OAuthError } from '@oidcraft/provider'
import { sendEmailSignIn } from '../op/accounts'
import { pendingSecondFactor } from './cookies'
import { type Flow, form, type Kit, lockedNotice, movesBrowsers, seeOther, signUp } from './kit'

const ADDRESS_MESSAGES = {
  required: 'Enter your email address',
  tooLong: 'That address is too long',
  invalid: 'That is not an email address'
} as const

/** Email sign-in (FR-I9): asked for at the sign-in, and the link it sends, which lands outside any interaction. */
export const emailFlow = ({ provider, accounts, screens, finish }: Kit) => {
  // FR-I9.2: every address gets the same page; what is sent, if anything, is the host's, and sign-up only where it is mounted.
  const interaction: Flow = async ({ request, action, view }) => {
    if (action !== 'email' || !movesBrowsers(view)) return undefined
    if (request.method === 'GET') return screens.email(view)
    const address = (await form(request)).get('email') ?? ''
    const issued = await accounts.emailSignIn.issue(address, view, signUp() ? { signUp: {} } : {})
    if (!issued.ok && issued.reason === 'address') {
      return screens.email(view, { address, error: ADDRESS_MESSAGES[issued.problem], status: 400 })
    }
    sendEmailSignIn(issued, provider.config.issuer)
    return screens.message('Check your email', 'If that address can sign in here by email, a link is on its way. It works once.')
  }

  /** Where an email sign-in link lands, in whichever browser it is opened, so outside any interaction (FR-I9.4). */
  const emailSignInRoutes = async (request: Request, url: URL) => {
    const expired = () =>
      screens.message('This link no longer works', 'It expired or was already used. Start again from the application.', 400)
    // Spending nothing on a sign-in already finished or expired, so a sign-up does not make an account nobody signs in to.
    const live = async (token: string) => {
      const found = await accounts.emailSignIn.find(token)
      const open = found && (await provider.interactions.find(found.interactionId).then(movesBrowsers, () => false))
      return open ? found : undefined
    }
    if (request.method === 'GET') {
      const token = url.searchParams.get('token') ?? ''
      const found = await live(token)
      return found ? screens.emailSignIn(token, found.address) : expired()
    }
    if (request.method !== 'POST') return new Response('Method not allowed', { status: 405 })
    // FR-I9.5: the token alone signs in any browser, so a page elsewhere posting one would sign its visitor in as whoever asked.
    if (request.headers.get('origin') !== new URL(provider.config.issuer).origin) {
      return screens.message('This sign-in cannot continue', 'Open the link from your email again.', 403)
    }
    const token = (await form(request)).get('token') ?? ''
    if (!(await live(token))) return expired()
    const result = await accounts.emailSignIn.redeem(token)
    if (!result.ok) {
      if (result.reason === 'passkey') {
        return screens.message(
          'Use your passkey',
          'This account signs in with a passkey. Start again from the application and use it.',
          400
        )
      }
      return result.reason === 'locked' ? screens.message('This account is locked', lockedNotice(result.lock), 429) : expired()
    }
    const { interactionId, accountId } = result
    if (result.secondFactor) {
      return seeOther(
        `/interaction/${encodeURIComponent(interactionId)}/otp`,
        await pendingSecondFactor.set(interactionId, accountId, true)
      )
    }
    try {
      return await finish(request, interactionId, accountId, ['email'])
    } catch (error) {
      if (!(error instanceof OAuthError)) console.error('[email sign-in]', error)
      return screens.message('This sign-in expired', 'Start again from the application.', 400)
    }
  }

  return { interaction, emailSignInRoutes }
}
