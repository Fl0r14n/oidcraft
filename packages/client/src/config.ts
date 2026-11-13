import type { OAuthTypeConfig } from '@oidcraft/core'
import { createStore } from './store'
import type { OAuthConfig } from './types'

export const createConfig = (cfg?: OAuthConfig) => {
  const configStore = createStore<{ oauthConfig: OAuthConfig }>({
    oauthConfig: {
      storageKey: 'token',
      ignorePaths: [],
      strictJwt: true,
      ...cfg
    }
  })

  const oauthConfig = () => configStore.getState().oauthConfig
  const setOAuthConfig = (patch: Partial<OAuthConfig>) => configStore.setState({ oauthConfig: { ...oauthConfig(), ...patch } })

  const config = () => oauthConfig().config
  const setConfig = (patch?: Partial<OAuthTypeConfig>) =>
    setOAuthConfig({ config: { ...oauthConfig().config, ...patch } as OAuthTypeConfig })

  const ignorePath = (pattern: RegExp) => {
    const paths = oauthConfig().ignorePaths ?? []
    if (!paths.some(p => p.source === pattern.source && p.flags === pattern.flags)) {
      setOAuthConfig({ ignorePaths: [...paths, pattern] })
    }
  }

  const isPathIgnored = (url?: string) => {
    const patterns = oauthConfig().ignorePaths ?? []
    if (!url || !patterns.length) return false
    // both forms: a pattern is usually written against the path, and the interceptor sees whatever
    // the caller passed, which is as often absolute as not
    const candidates = [url]
    try {
      candidates.push(new URL(url, 'http://localhost').pathname)
    } catch {}
    return patterns.some(pattern => candidates.some(candidate => pattern.test(candidate)))
  }

  const originOf = (url: string | undefined) => {
    try {
      return url ? new URL(url).origin : undefined
    } catch {
      return undefined
    }
  }

  /**
   * RFC 9700 §2.3: a bearer token goes where it is meant for — this page's origin, the provider's,
   * and the origins the application names — never to whatever URL a call happens to be for (FR-L6).
   * A relative URL is this page's. No URL is the caller asking for the headers themselves.
   */
  const isResourceUrl = (url?: string) => {
    if (!url || !URL.canParse(url)) return true
    const { issuerPath, issuer, userPath } = (config() ?? {}) as { issuerPath?: string; issuer?: string; userPath?: string }
    const allowed = [globalThis.location?.origin, ...[issuerPath, issuer, userPath].map(originOf), ...(oauthConfig().resourceOrigins ?? [])]
    return allowed.includes(new URL(url).origin)
  }

  const storageKey = () => oauthConfig().storageKey || 'token'
  const setStorageKey = (storageKey: string) => setOAuthConfig({ storageKey })

  const strictJwt = () => oauthConfig().strictJwt

  return {
    configStore,
    oauthConfig,
    setOAuthConfig,
    config,
    setConfig,
    ignorePath,
    isPathIgnored,
    isResourceUrl,
    storageKey,
    setStorageKey,
    strictJwt
  }
}

export type ConfigContext = ReturnType<typeof createConfig>
