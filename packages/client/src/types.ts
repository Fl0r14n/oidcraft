import type { Discovery, OAuthFunctions, OAuthTypeConfig } from '@oidcraft/core'

export type OAuthConfig<TExtra = unknown> = {
  config?: Partial<OAuthTypeConfig>
  storageKey?: string
  ignorePaths?: RegExp[]
  /** Origins the access token may be sent to besides this page's and the provider's, e.g. `https://api.example.com` (FR-L6). */
  resourceOrigins?: string[]
  strictJwt?: boolean
  functions?: Partial<OAuthFunctions>
  /** share one across per-request instances to fetch each issuer's well-known document once; omitted, each instance has its own */
  discovery?: Discovery
  /** off leaves the instance inert until `start()` */
  autoStart?: boolean
} & TExtra

/** `redirect: false` returns the URL instead of navigating. */
export type RedirectOptions = { redirect?: boolean }
