import type { ResolvedConfig } from '../config'

type Issuer = Pick<ResolvedConfig, 'issuerUrl'>

export const isSecure = (config: Issuer) => config.issuerUrl.protocol === 'https:'

/** One cookie per issuer: two issuers on one host, told apart by path, would otherwise overwrite each other's. */
const perIssuer = (config: Issuer, name: string) => {
  const { pathname } = config.issuerUrl
  let start = 0
  let end = pathname.length
  while (start < end && pathname[start] === '/') start++
  while (end > start && pathname[end - 1] === '/') end--
  const path = pathname.slice(start, end)
  return path ? `${name}.${path.replace(/[^A-Za-z0-9]/g, '_')}` : name
}

/**
 * Every cookie the provider sets is named here (S-10): `__Host-` on an https issuer, so the browser keeps it host-only,
 * `Path=/` and `Secure`, and a sibling subdomain can neither read it nor plant one of its own.
 */
export const issuerCookie = (config: Issuer, name: string) => perIssuer(config, `${isSecure(config) ? '__Host-' : ''}${name}`)

export const parseCookies = (header: string | null) => {
  const out = new Map<string, string>()
  if (!header) return out
  for (const pair of header.split(';')) {
    const separator = pair.indexOf('=')
    if (separator < 0) continue
    // A cookie this provider never set, or one mangled in transit, is ignored rather than a 500.
    try {
      out.set(pair.slice(0, separator).trim(), decodeURIComponent(pair.slice(separator + 1).trim()))
    } catch {}
  }
  return out
}

export type CookieOptions = {
  maxAge?: number
  secure?: boolean
  path?: string
  sameSite?: 'Lax' | 'Strict' | 'None'
}

/** HttpOnly always: a session cookie readable from script is a session cookie an XSS exfiltrates. */
export const serializeCookie = (name: string, value: string, options: CookieOptions = {}) => {
  const parts = [`${name}=${encodeURIComponent(value)}`, `Path=${options.path ?? '/'}`, 'HttpOnly', `SameSite=${options.sameSite ?? 'Lax'}`]
  if (options.secure !== false) parts.push('Secure')
  if (options.maxAge !== undefined) parts.push(`Max-Age=${options.maxAge}`)
  return parts.join('; ')
}

export const clearCookie = (name: string, options: CookieOptions = {}) => serializeCookie(name, '', { ...options, maxAge: 0 })
