import type { OAuthFetch } from '@oidcraft/core'
import type { ConfigContext } from './config'
import type { TokenContext } from './token'

export const createFetch = (
  { isPathIgnored }: Pick<ConfigContext, 'isPathIgnored'>,
  { setToken, accessToken, checkToken }: Pick<TokenContext, 'setToken' | 'accessToken' | 'checkToken'>
) => {
  const authHeaders = async (url?: string): Promise<Record<string, string>> => {
    if (isPathIgnored(url)) return {}
    await checkToken()
    const bearer = accessToken()
    return (bearer && { Authorization: bearer }) || {}
  }

  const oauthFetch: OAuthFetch = async (input, init) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
    const headers = new Headers(init?.headers)
    for (const [key, value] of Object.entries(await authHeaders(url))) {
      headers.set(key, value)
    }
    if (typeof init?.body === 'string' && !headers.has('Content-Type')) {
      headers.set('Content-Type', 'application/json')
    }
    if (!headers.has('Accept')) {
      headers.set('Accept', 'application/json')
    }
    const response = await fetch(input, { ...init, headers })
    if (response.status === 401) {
      // the resource server's answer replaces the token, so a dead credential is dropped rather than
      // resent on every subsequent call
      const body = await response
        .clone()
        .json()
        .catch(() => undefined)
      setToken((typeof body === 'object' && body) || {})
    }
    return response
  }

  return { authHeaders, oauthFetch }
}

export type FetchContext = ReturnType<typeof createFetch>
