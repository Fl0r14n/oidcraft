import { OAuthError } from '../errors'

/** Registration refuses with RFC 7591's codes; a metadata document, read at the authorization endpoint, does not. */
export type Refuse = (description: string) => OAuthError

export const invalidMetadata: Refuse = description =>
  new OAuthError('invalid_client_metadata', { description, spec: 'RFC 7591 §3.2.2', status: 400 })

// RFC 8252 §8.3: loopback means the IP literal. `localhost` can be resolved elsewhere.
const isLoopbackIp = (url: URL) => url.hostname === '127.0.0.1' || url.hostname === '[::1]'

// Each would run script, or read a file, wherever the browser is sent or a form is posted.
const FORBIDDEN_SCHEMES = ['javascript:', 'data:', 'vbscript:', 'file:']

/** A URL the browser is sent to: a redirect or a post-logout redirect (NFR-S2). */
export const browserUri = (
  raw: unknown,
  name: string,
  { native = false, fail = invalidMetadata }: { native?: boolean; fail?: Refuse } = {}
) => {
  if (typeof raw !== 'string' || !URL.canParse(raw)) throw fail(`${name} ${String(raw)} is not an absolute URL`)
  const url = new URL(raw)
  // A fragment can never be matched: the browser never sends it (RFC 6749 §3.1.2).
  if (url.hash) throw fail(`${name} ${raw} must not carry a fragment`)
  if (FORBIDDEN_SCHEMES.includes(url.protocol)) throw fail(`${name} ${raw} uses a scheme that can run script`)
  // A native app listens on this machine, and many say localhost: its port is free, as on a loopback IP (NFR-S2).
  const local = isLoopbackIp(url) || (native && url.hostname === 'localhost')
  if (url.protocol === 'http:' && !local) {
    throw fail(`${name} ${raw} must be https outside a loopback IP${native ? ' or localhost' : ''}`)
  }
  return raw
}

// WHATWG URL parsing already turns decimal, octal and hex forms of an IPv4 address into the dotted one.
const isIpLiteral = (hostname: string) => hostname.startsWith('[') || /^\d+\.\d+\.\d+\.\d+$/.test(hostname)

/**
 * A URL the host fetches or posts to on a client's say-so (NFR-S14): https, a public name, no credentials. A name
 * that resolves inside the network is the host's to refuse when it fetches, since only it resolves names (FR-A1).
 */
export const serverUriProblem = (raw: unknown, name: string) => {
  if (typeof raw !== 'string' || !URL.canParse(raw)) return `${name} ${String(raw)} is not an absolute URL`
  const url = new URL(raw)
  if (url.protocol !== 'https:') return `${name} ${raw} must be https`
  if (url.hash) return `${name} ${raw} must not carry a fragment`
  if (url.username || url.password) return `${name} must not carry credentials`
  if (isIpLiteral(url.hostname) || url.hostname === 'localhost' || url.hostname.endsWith('.localhost')) {
    return `${name} ${raw} must name a public host, not an address or localhost`
  }
  return undefined
}

export const serverUri = (raw: unknown, name: string, fail: Refuse = invalidMetadata) => {
  const problem = serverUriProblem(raw, name)
  if (problem) throw fail(problem)
  return raw as string
}

/** The fields of a stored client the host fetches or posts to, whoever wrote the client (NFR-S14). */
export const SERVER_URI_FIELDS = {
  jwksUri: 'jwks_uri',
  sectorIdentifierUri: 'sector_identifier_uri',
  backchannelLogoutUri: 'backchannel_logout_uri',
  backchannelClientNotificationEndpoint: 'backchannel_client_notification_endpoint'
} as const
