import type { Client, Expiring } from '@oidcraft/provider'
import type { InteractionRequest } from '@oidcraft/provider/interaction'
import type { ScreenView } from '@oidcraft/ui'
import { optional } from '../op/env'
import type { Site } from '../op/site'
import { upstreamLabels } from './broker'
import { knownAccounts, pendingSecondFactor } from './cookies'

export const seeOther = (location: string, ...cookies: (string | undefined)[]) => {
  const headers = new Headers({ location, 'cache-control': 'no-store' })
  for (const cookie of cookies) if (cookie) headers.append('set-cookie', cookie)
  return new Response(null, { status: 303, headers })
}

export const withCookie = async (response: Promise<Response>, cookie: string) => {
  const sent = await response
  sent.headers.append('set-cookie', cookie)
  return sent
}

export const form = async (request: Request) => new URLSearchParams(await request.text())

export const parsed = (text: string | null) => {
  try {
    return JSON.parse(text ?? '')
  } catch {
    return undefined
  }
}

/** Sign-up is on unless OIDCRAFT_SIGNUP=off: a deployment that provisions accounts itself leaves it unmounted. */
export const signUp = () => optional('OIDCRAFT_SIGNUP') !== 'off'

/** FR-I9.4: only an authorization sign-in can finish in the browser a link is opened in; a device one has no redirect URI. */
export const movesBrowsers = (view: InteractionRequest) => view.redirectUri !== undefined

export const lockedNotice = (lock: Expiring) =>
  `Too many attempts. Try again after ${new Date(lock.expiresAt).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })}.`

const USERNAME_MESSAGES = {
  required: 'Choose a username',
  tooLong: 'That username is too long',
  invalid: 'Use letters, digits and punctuation, without spaces',
  taken: 'That username is taken'
} as const

export const usernameMessage = (problem: keyof typeof USERNAME_MESSAGES) => USERNAME_MESSAGES[problem]

/** What the sign-in a reset led back to says first, by a fixed key: the query names it, never words it. */
export const afterReset = (changed: string | null) =>
  changed === 'password'
    ? 'Your password was changed. Sign in with the new one.'
    : changed === 'passkey'
      ? 'Your passkey was added. Sign in with it, then remove the one you lost from your account: it still signs in.'
      : undefined

const offeredUpstreams = (view: InteractionRequest) =>
  upstreamLabels([...new Set([view.upstream?.chosen, ...(view.upstream?.candidates ?? [])].filter(id => id !== undefined))])

/** An interaction request as a route handles it: the view the screens render, and where it was asked. */
export type Step = {
  request: Request
  url: URL
  id: string
  action: string | undefined
  view: ScreenView
  client: Client | undefined
  clientIp: string | undefined
}

/** What every flow shares: the site's provider, accounts and screens, and the steps more than one flow ends in. */
export const createKit = (site: Site) => {
  const { provider, accounts, screens } = site

  const loginScreen = (view: ScreenView, options: Parameters<typeof screens.login>[1] = {}) =>
    screens.login(view, {
      upstreams: offeredUpstreams(view),
      forgot: true,
      register: signUp(),
      passkeys: true,
      recover: true,
      email: movesBrowsers(view),
      ...options
    })

  const secondStep = async (view: ScreenView, accountId: string, options: Parameters<typeof screens.otp>[1] = {}) =>
    screens.otp(view, { passkeys: (await accounts.passkeys.list(accountId)).length > 0, ...options })

  /** The acr says what happened (FR-F9, FR-C16); only a sign-in proven by email may finish in another browser (FR-I9.4, FR-I2). */
  const finish = async (request: Request, id: string, accountId: string, amr: string[], acr = amr.includes('mfa') ? 'mfa' : 'pwd') => {
    const login = { accountId, acr, amr }
    const cookie = request.headers.get('cookie')
    const { redirectTo, setCookie } = amr.includes('email')
      ? await provider.interactions.completeHere(id, login, cookie)
      : await provider.interactions.complete(id, { login }, cookie)
    return seeOther(redirectTo, setCookie, pendingSecondFactor.clear(), await knownAccounts.add(request, accountId))
  }

  return { site, provider, accounts, screens, loginScreen, secondStep, finish }
}

export type Kit = ReturnType<typeof createKit>

/** A flow's share of the interaction routes: a response for an action it owns, or undefined to let the next flow look. */
export type Flow = (step: Step) => Promise<Response | undefined>
