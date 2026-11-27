import { randomString } from '@oidcraft/core'
import { storedId } from '../artifacts'
import type { ResolvedConfig } from '../config'
import { OAuthError } from '../errors'
import { isSecure, issuerCookie, parseCookies, serializeCookie } from './cookies'

const browserCookie = (config: Pick<ResolvedConfig, 'issuerUrl'>) => issuerCookie(config, 'oidcraft.browser')

// FR-I2: unbound, a page could post an attacker's credentials to their interaction from the victim's browser.
export const bindBrowser = async (config: ResolvedConfig, cookie: string | null | undefined) => {
  const held = parseCookies(cookie ?? null).get(browserCookie(config))
  const value = held || randomString()
  return {
    browser: await storedId(value),
    setCookie: held ? undefined : serializeCookie(browserCookie(config), value, { secure: isSecure(config) })
  }
}

export const isSameBrowser = async (config: ResolvedConfig, cookie: string | null | undefined, browser: string) => {
  const held = parseCookies(cookie ?? null).get(browserCookie(config))
  return held !== undefined && held !== '' && (await storedId(held)) === browser
}

export const assertSameBrowser = async (config: ResolvedConfig, cookie: string | null | undefined, browser: string) => {
  if (!(await isSameBrowser(config, cookie, browser))) {
    throw new OAuthError('invalid_request', {
      description: 'this interaction was started in another browser',
      status: 403,
      spec: 'FR-I2'
    })
  }
}
