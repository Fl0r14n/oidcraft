/** Thrown, never swallowed into `undefined`: an `http` endpoint is a misconfiguration, not an outage. */
export class InsecureEndpointError extends Error {
  readonly url: string

  constructor(url: string) {
    super(`refusing to use ${url} over plain http: set allowInsecure to permit it in development`)
    this.name = 'InsecureEndpointError'
    this.url = url
  }
}

const SCHEME = /^([a-z][a-z0-9+.-]*):/i

/** WHATWG URL §4.4: the parser drops leading C0 controls and spaces and every tab and newline, so the scheme is read as it will. */
const asParsed = (url: string) => {
  const stripped = url.replace(/[\t\n\r]/g, '')
  let start = 0
  while (start < stripped.length && stripped.charCodeAt(start) <= 0x20) start++
  return stripped.slice(start)
}

/** Every absolute endpoint must be https unless `allowInsecure` is set; `localhost` is not exempt. */
export const assertSecure = <T extends string | undefined>(url: T, allowInsecure?: boolean): T => {
  if (!url || allowInsecure) return url
  const scheme = SCHEME.exec(asParsed(url))?.[1]?.toLowerCase()
  // a relative path inherits the document's origin
  if (!scheme || scheme === 'https') return url
  throw new InsecureEndpointError(url)
}

/** Entra's multi-tenant issuer placeholder; it never matches `iss` literally, so the id-token verifier resolves it per token. */
export const TENANT_TEMPLATE = '{tenantid}'

const trimmed = (url: string) => {
  let end = url.length
  while (end > 0 && url[end - 1] === '/') end--
  return url.slice(0, end)
}

/** Issuers compare as strings (OIDC Discovery 1.0 §4.3, RFC 9207 §2.4), ignoring only a trailing slash. */
export const sameIssuer = (a: string, b: string) => trimmed(a) === trimmed(b)

export const isTenantTemplate = (issuer?: string) => !!issuer?.includes(TENANT_TEMPLATE)
