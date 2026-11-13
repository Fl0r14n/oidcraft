import { randomString } from '@oidcraft/core'
import { storedId } from '../artifacts'
import type { ResolvedConfig } from '../config'
import { OAuthError } from '../errors'
import { parseCookies, serializeCookie } from './cookies'
import { perIssuer } from './session'

const secure = (config: Pick<ResolvedConfig, 'issuerUrl'>) => config.issuerUrl.protocol === 'https:'

// `__Host-` where the browser honours it: a sibling subdomain cannot plant the cookie and so cannot share a browser's binding.
const browserCookie = (config: Pick<ResolvedConfig, 'issuerUrl'>) => perIssuer(config, `${secure(config) ? '__Host-' : ''}oidcraft.browser`)

/**
 * What an interaction is bound to: the browser that was sent to it (FR-I2). Without it, a page could
 * post an attacker's own credentials to the attacker's interaction from the victim's browser, and
 * the session that results would be the victim's. One cookie per browser, so tabs do not evict each other.
 */
export const bindBrowser = async (config: ResolvedConfig, cookie: string | null | undefined) => {
  const held = parseCookies(cookie ?? null).get(browserCookie(config))
  const value = held || randomString()
  return {
    browser: await storedId(value),
    setCookie: held ? undefined : serializeCookie(browserCookie(config), value, { secure: secure(config) })
  }
}

export const assertSameBrowser = async (config: ResolvedConfig, cookie: string | null | undefined, browser: string) => {
  const held = parseCookies(cookie ?? null).get(browserCookie(config))
  if (!held || (await storedId(held)) !== browser) {
    throw new OAuthError('invalid_request', {
      description: 'this interaction was started in another browser',
      status: 403,
      spec: 'FR-I2'
    })
  }
}
