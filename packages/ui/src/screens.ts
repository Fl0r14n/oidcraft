import { DEFAULT_MAX_LENGTH, type InteractionRequest, type OAuthFieldError, type OAuthFieldErrors } from 'oidcraft/interaction'
import type { Brand, Theme } from './brand'
import { render } from './render'
import ConsentScreen from './screens/ConsentScreen.vue'
import DeviceCodeScreen from './screens/DeviceCodeScreen.vue'
import LoginScreen from './screens/LoginScreen.vue'
import LogoutScreen from './screens/LogoutScreen.vue'
import MessageScreen from './screens/MessageScreen.vue'
import SelectAccountScreen from './screens/SelectAccountScreen.vue'
import TotpScreen from './screens/TotpScreen.vue'

/** What a rejected POST hands back to the screen, so the attempt is not thrown away. */
export type LoginAttempt = { username: string; errors: OAuthFieldErrors }

/** Where each form posts. Passed in, so the screens can sit under any prefix an issuer uses (G-6). */
export type ScreenUrls = {
  interaction: (id: string, action: 'login' | 'upstream' | 'consent' | 'logout' | 'otp') => string
  device: string
  deviceDecide: string
}

/** The interaction as the provider describes it, plus the client's display name when the host has it. */
export type ScreenView = InteractionRequest & { clientName?: string | undefined }

const nameOf = (view: ScreenView) => view.clientName ?? view.clientId

export type ScreensOptions = { brand: Brand; theme?: Theme | undefined; urls?: Partial<ScreenUrls> }

/** Codes come from `oidcraft/interaction`; the wording is this screen's, and its locale's (FR-I6). */
const MESSAGES: Record<'username' | 'password', Record<'required' | 'tooLong', string>> = {
  username: { required: 'Enter your username', tooLong: `Use at most ${DEFAULT_MAX_LENGTH} characters` },
  password: { required: 'Enter your password', tooLong: `Use at most ${DEFAULT_MAX_LENGTH} characters` }
}

const message = (field: 'username' | 'password', error: OAuthFieldError) => (error ? MESSAGES[field][error] : undefined)

const DESCRIPTIONS: Record<string, string> = {
  openid: 'Confirm who you are',
  profile: 'See your name and profile details',
  email: 'See your email address',
  offline_access: 'Stay connected when you are not using it'
}

const describe = (scope: string) => DESCRIPTIONS[scope] ?? scope

/** The screens for one brand. Build once per issuer; every call renders a complete response. */
export const createScreens = ({ brand, theme, urls: overrides }: ScreensOptions) => {
  const urls: ScreenUrls = {
    interaction: (id, action) => `/interaction/${encodeURIComponent(id)}/${action}`,
    device: '/device',
    deviceDecide: '/device/decide',
    ...overrides
  }
  const page = (title: string, component: Parameters<typeof render>[1], props: Record<string, unknown>, status?: number) =>
    render(title, component, props, { brand, theme, status })

  const messageScreen = (title: string, text: string, status?: number) => page(title, MessageScreen, { title, text }, status)

  return {
    /**
     * `required` and `maxlength` are the browser's copy of the rules the POST re-checks with
     * `oauthFieldError`. Both are needed: the attribute is absent the moment someone posts without a browser.
     */
    login: (view: ScreenView, attempt?: LoginAttempt, upstreams: { id: string; label: string }[] = [], status?: number) =>
      page(
        'Sign in',
        LoginScreen,
        {
          action: urls.interaction(view.id, 'login'),
          upstreamAction: urls.interaction(view.id, 'upstream'),
          clientName: nameOf(view),
          username: attempt?.username ?? view.loginHint ?? '',
          maxLength: DEFAULT_MAX_LENGTH,
          errors: { username: message('username', attempt?.errors.username), password: message('password', attempt?.errors.password) },
          upstreams
        },
        status
      ),

    otp: (view: ScreenView, error?: string, status?: number) =>
      page('Enter your code', TotpScreen, { action: urls.interaction(view.id, 'otp'), brandName: brand.name, error }, status),

    selectAccount: (view: ScreenView, accounts: { accountId: string; label: string }[]) =>
      page('Choose an account', SelectAccountScreen, { action: urls.interaction(view.id, 'login'), clientName: nameOf(view), accounts }),

    consent: (view: ScreenView) =>
      page('Allow access', ConsentScreen, {
        action: urls.interaction(view.id, 'consent'),
        title: `Allow ${nameOf(view)} to use your account?`,
        intro: `It is asking to:`,
        scopes: view.scopes.map(describe),
        details: (view.authorizationDetails ?? []).map(detail => JSON.stringify(detail, null, 2))
      }),

    /**
     * Reached by a person typing a code they read elsewhere, so it accepts the code in whatever
     * shape they typed it (RFC 8628 §6.1) and says plainly what approving means.
     */
    deviceCode: (code = '', error = '', status?: number) =>
      page('Connect a device', DeviceCodeScreen, { action: urls.device, code, error }, status),

    deviceConfirm: (userCode: string, clientName: string, scopes: string[]) =>
      page('Allow the device', ConsentScreen, {
        action: urls.deviceDecide,
        title: `Allow ${clientName} to use your account?`,
        intro: `The device showing ${userCode} is asking to:`,
        scopes: scopes.map(describe),
        details: [],
        hidden: { user_code: userCode }
      }),

    deviceDone: (approved: boolean) =>
      approved
        ? messageScreen('Device connected', 'Go back to the device. It continues on its own.')
        : messageScreen('Device not connected', 'Nothing was shared with the device.'),

    logout: (id: string, clientName: string | undefined) =>
      page('Sign out', LogoutScreen, { action: urls.interaction(id, 'logout'), brandName: brand.name, clientName }),

    message: messageScreen,

    /** OIDC Core §3.1.2.6: an error that cannot go back to the client is shown to the user instead. */
    error: (error: string, description: string | undefined, status = 400) =>
      page(
        'Sign-in error',
        MessageScreen,
        {
          title: 'This sign-in cannot continue',
          text: 'The application that sent you here made a request this server cannot accept. Go back to it and try again.',
          error: description ? `${error}: ${description}` : error
        },
        status
      )
  }
}

export type Screens = ReturnType<typeof createScreens>
