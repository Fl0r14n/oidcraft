import { DEFAULT_MAX_LENGTH, type InteractionRequest, type OAuthFieldError, type OAuthFieldErrors } from 'oidcraft/interaction'
import { render } from './render'
import ConsentScreen from './screens/ConsentScreen.vue'
import DeviceCodeScreen from './screens/DeviceCodeScreen.vue'
import LoginScreen from './screens/LoginScreen.vue'
import LogoutScreen from './screens/LogoutScreen.vue'
import MessageScreen from './screens/MessageScreen.vue'
import SelectAccountScreen from './screens/SelectAccountScreen.vue'

/** What a rejected POST hands back to the screen, so the attempt is not thrown away. */
export type LoginAttempt = { username: string; errors: OAuthFieldErrors }

/** Codes come from `oidcraft/interaction`; the wording is this screen's, and its locale's (FR-I6). */
const MESSAGES: Record<'username' | 'password', Record<'required' | 'tooLong', string>> = {
  username: { required: 'Enter your username', tooLong: `Use at most ${DEFAULT_MAX_LENGTH} characters` },
  password: { required: 'Enter your password', tooLong: `Use at most ${DEFAULT_MAX_LENGTH} characters` }
}

const message = (field: 'username' | 'password', error: OAuthFieldError) => (error ? MESSAGES[field][error] : undefined)

const DESCRIPTIONS: Record<string, string> = {
  openid: 'confirm who you are',
  profile: 'see your name and profile details',
  email: 'see your email address',
  offline_access: 'stay signed in when you are away'
}

const describe = (scope: string) => DESCRIPTIONS[scope] ?? scope

/**
 * `required` and `maxlength` are the browser's copy of the rules the POST re-checks with
 * `oauthFieldError`. Both are needed: the attribute is absent the moment someone posts without a browser.
 */
export const loginScreen = (
  view: InteractionRequest,
  attempt?: LoginAttempt,
  upstreams: { id: string; label: string }[] = [],
  status = 200
) =>
  render(
    'Sign in',
    LoginScreen,
    {
      action: `/interaction/${view.id}/login`,
      upstreamAction: `/interaction/${view.id}/upstream`,
      clientId: view.clientId,
      username: attempt?.username ?? view.loginHint ?? '',
      maxLength: DEFAULT_MAX_LENGTH,
      errors: { username: message('username', attempt?.errors.username), password: message('password', attempt?.errors.password) },
      upstreams
    },
    status
  )

export const selectAccountScreen = (view: InteractionRequest, accounts: { accountId: string; label: string }[]) =>
  render('Choose an account', SelectAccountScreen, { action: `/interaction/${view.id}/login`, clientId: view.clientId, accounts })

export const consentScreen = (view: InteractionRequest) =>
  render('Authorize', ConsentScreen, {
    action: `/interaction/${view.id}/consent`,
    clientName: view.clientId,
    intro: 'It is asking to:',
    scopes: view.scopes.map(describe),
    details: (view.authorizationDetails ?? []).map(detail => JSON.stringify(detail, null, 2))
  })

/**
 * The device screen is reached by a person typing a code they read elsewhere, so it accepts the
 * code in whatever shape they typed it (RFC 8628 §6.1) and says plainly what approving means.
 */
export const deviceCodeScreen = (code = '', error = '', status = 200) => render('Enter the code', DeviceCodeScreen, { code, error }, status)

export const deviceConfirmScreen = (userCode: string, clientName: string, scopes: string[]) =>
  render('Authorize the device', ConsentScreen, {
    action: '/device/decide',
    clientName,
    intro: `Code ${userCode}. It is asking to:`,
    scopes: scopes.map(describe),
    details: [],
    hidden: { user_code: userCode }
  })

export const deviceDoneScreen = (approved: boolean) =>
  approved
    ? messageScreen('You are all set', 'Return to the device — it will continue on its own.')
    : messageScreen('Denied', 'Nothing was shared with the device.')

export const logoutConfirmScreen = (id: string, clientName: string | undefined) =>
  render('Sign out', LogoutScreen, { action: `/interaction/${encodeURIComponent(id)}/logout`, clientName })

export const messageScreen = (title: string, text: string, status = 200) => render(title, MessageScreen, { title, text }, status)

/** OIDC Core §3.1.2.6: an error that cannot go back to the client is shown to the user instead. */
export const errorScreen = (error: string, description: string | undefined, status = 400) =>
  render(
    'Sign-in error',
    MessageScreen,
    {
      title: 'This sign-in cannot continue',
      text: 'The application sent an invalid request.',
      error: description ? `${error}: ${description}` : error
    },
    status
  )
