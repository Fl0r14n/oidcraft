import type { OAuthTypeConfig } from '@oidcraft/core'
import { createStore } from './store'
import type { OAuthConfig } from './types'

/** Stands in for the page's origin when there is no page to resolve a relative URL against. */
const THIS_PAGE = 'https://this-page.invalid'

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

  // RFC 9700 §2.3, FR-L6: the bearer goes only to this page's origin, the provider's and `resourceOrigins`.
  // Resolved as the browser will: `//host/x` and `\\host\x` parse only against a base, and land on another origin.
  // Without a page to resolve against, a path still means this page, and anything that names a host does not.
  const isResourceUrl = (url?: string) => {
    if (!url) return true
    const page = globalThis.location?.origin && globalThis.location.origin !== 'null' ? globalThis.location.href : undefined
    const base = page ?? THIS_PAGE
    if (!URL.canParse(url, base)) return false
    const target = new URL(url, base).origin
    if (!page && target === THIS_PAGE) return true
    const { issuerPath, issuer, userPath } = (config() ?? {}) as { issuerPath?: string; issuer?: string; userPath?: string }
    const allowed = [
      page && globalThis.location.origin,
      ...[issuerPath, issuer, userPath].map(originOf),
      ...(oauthConfig().resourceOrigins ?? [])
    ]
    return allowed.includes(target)
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
