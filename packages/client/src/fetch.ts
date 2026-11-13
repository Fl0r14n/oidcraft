import type { OAuthFetch } from '@oidcraft/core'
import type { ConfigContext } from './config'
import type { TokenContext } from './token'

export const createFetch = (
  { isPathIgnored, isResourceUrl }: Pick<ConfigContext, 'isPathIgnored' | 'isResourceUrl'>,
  { setToken, accessToken, checkToken }: Pick<TokenContext, 'setToken' | 'accessToken' | 'checkToken'>
) => {
  const carriesToken = (url?: string) => !isPathIgnored(url) && isResourceUrl(url)

  const authHeaders = async (url?: string): Promise<Record<string, string>> => {
    if (!carriesToken(url)) return {}
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
      onUnauthorized(
        url,
        await response
          .clone()
          .json()
          .catch(() => undefined)
      )
    }
    return response
  }

  // FR-L6: a 401 from where the token went ends it; only the body's error fields become the token state.
  const onUnauthorized = (url: string | undefined, body: unknown) => {
    if (!carriesToken(url)) return
    const { error, error_description } = (typeof body === 'object' && body ? body : {}) as Record<string, unknown>
    setToken({
      ...(typeof error === 'string' && { error }),
      ...(typeof error_description === 'string' && { error_description })
    })
  }

  return { authHeaders, oauthFetch, onUnauthorized }
}

export type FetchContext = ReturnType<typeof createFetch>
