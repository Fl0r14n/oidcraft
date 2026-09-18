import type { Discovery, OAuthFunctions, OAuthTypeConfig } from '@oidcraft/core'

export type OAuthConfig<TExtra = unknown> = {
  config?: Partial<OAuthTypeConfig>
  storageKey?: string
  ignorePaths?: RegExp[]
  strictJwt?: boolean
  functions?: Partial<OAuthFunctions>
  /** share one across per-request instances to fetch each issuer's well-known document once; omitted,
   * the instance gets its own, which still collapses concurrent lookups into a single request */
  discovery?: Discovery
  /** off leaves the instance inert until `start()`. Construction is already side-effect free; this
   * only decides whether `createOAuth` arms it for you. */
  autoStart?: boolean
} & TExtra

/** Whether a call that would navigate the browser is allowed to. Off returns the URL instead, for a
 * caller doing its own routing, and for a test. */
export type RedirectOptions = { redirect?: boolean }
