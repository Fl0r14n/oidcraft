/** Thrown, where the request layer returns `undefined`, because the two failures are not the same
 * kind: an unreachable endpoint is the network's answer, and an `http` endpoint is the caller's own
 * configuration. Swallowing the second into `undefined` would report a misconfiguration as an outage. */
export class InsecureEndpointError extends Error {
  readonly url: string

  constructor(url: string) {
    super(`refusing to use ${url} over plain http: set allowInsecure to permit it in development`)
    this.name = 'InsecureEndpointError'
    this.url = url
  }
}

const SCHEME = /^([a-z][a-z0-9+.-]*):/i

/**
 * A code, a token or a client secret crossing plain http is already in the hands of anyone on the
 * path, so every absolute endpoint must be https unless the caller says otherwise. `localhost` is
 * not exempt: `allowInsecure` is the one way to say it, and saying it is cheap.
 */
export const assertSecure = <T extends string | undefined>(url: T, allowInsecure?: boolean): T => {
  if (!url || allowInsecure) return url
  const scheme = SCHEME.exec(url)?.[1]?.toLowerCase()
  // A relative path inherits the document's origin. There is nothing here to check, and nothing this
  // library could do about it if there were.
  if (!scheme || scheme === 'https') return url
  throw new InsecureEndpointError(url)
}

/** Entra's multi-tenant document advertises this in place of an issuer, because the tenant is not
 * known until a token arrives. It can never match an `iss` literally, so any comparison against it
 * is deferred to the id-token verifier, which resolves it per token. */
export const TENANT_TEMPLATE = '{tenantid}'

const trimmed = (url: string) => url.replace(/\/+$/, '')

/** Issuer identifiers are compared as strings (OIDC Discovery 1.0 §4.3, RFC 9207 §2.4); a trailing
 * slash is the one difference that is never meaningful and is always someone's copy-paste. */
export const sameIssuer = (a: string, b: string) => trimmed(a) === trimmed(b)

export const isTenantTemplate = (issuer?: string) => !!issuer?.includes(TENANT_TEMPLATE)
