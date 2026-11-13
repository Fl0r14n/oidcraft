export type RedirectFlow = 'implicit' | 'code' | 'none'

export type RedirectSource = string | URL | { hash?: string; search?: string }

export type ParsedRedirect = {
  flow: RedirectFlow
  parameters: Record<string, string>
}

const parts = (source?: RedirectSource) => {
  if (!source) return {}
  if (typeof source === 'string') return new URL(source)
  return source
}

const parseOauthUri = (fragment?: string) => {
  const params = Object.fromEntries(new URLSearchParams(fragment?.replace(/^[#?]/, '')))
  return (Object.keys(params).length && params) || {}
}

/** Classifies a redirect from the authorization endpoint; an `error=` is still that flow's response (RFC 6749 §4.1.2.1). */
export const parseRedirectParameters = (source?: RedirectSource): ParsedRedirect => {
  const { hash, search } = parts(source)
  // By parameter name, not substring: an app's own `?barcode=` is not a code.
  const fragment = parseOauthUri(hash)
  const query = parseOauthUri(search)
  if ('access_token' in fragment || 'error' in fragment) return { flow: 'implicit', parameters: fragment }
  if ('code' in query || 'error' in query) return { flow: 'code', parameters: query }
  if ('code' in fragment) return { flow: 'code', parameters: fragment }
  return { flow: 'none', parameters: {} }
}
