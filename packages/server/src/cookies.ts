export const parseCookies = (header: string | null) => {
  const out = new Map<string, string>()
  if (!header) return out
  for (const pair of header.split(';')) {
    const separator = pair.indexOf('=')
    if (separator < 0) continue
    out.set(pair.slice(0, separator).trim(), decodeURIComponent(pair.slice(separator + 1).trim()))
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
