/** A URL a client chose, refused before or while it is fetched (NFR-S14). */
export class UnsafeFetchError extends Error {
  readonly url: string

  constructor(url: string, reason: string) {
    super(`refusing to fetch ${url}: ${reason}`)
    this.name = 'UnsafeFetchError'
    this.url = url
  }
}

const octets = (address: string) => {
  const parts = address.split('.')
  return parts.length === 4 && parts.every(part => /^\d{1,3}$/.test(part) && Number(part) <= 255) ? parts.map(Number) : undefined
}

// RFC 6890: this network, private, loopback, CGNAT, link-local (cloud metadata at 169.254.169.254), IETF protocol
// assignments, documentation, benchmarking, multicast and reserved.
const publicV4 = ([a = 0, b = 0, c = 0]: number[]) =>
  !(
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 0 && (c === 0 || c === 2)) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19)) ||
    (a === 198 && b === 51 && c === 100) ||
    (a === 203 && b === 0 && c === 113) ||
    a >= 224
  )

/** Eight 16-bit groups, `::` expanded and a dotted tail read as two of them. */
const groups = (address: string) => {
  const dotted = /^(.*:)(\d+\.\d+\.\d+\.\d+)$/.exec(address)
  const tail = dotted ? octets(dotted[2] as string) : undefined
  if (dotted && !tail) return undefined
  const head = dotted ? `${dotted[1]}${((tail?.[0] ?? 0) << 8) | (tail?.[1] ?? 0)}:${((tail?.[2] ?? 0) << 8) | (tail?.[3] ?? 0)}` : address
  const halves = head.split('::')
  if (halves.length > 2) return undefined
  const parse = (half: string) =>
    half ? half.split(':').map(group => (dotted && group === '' ? Number.NaN : Number.parseInt(group, 16))) : []
  const [left = [], right = []] = halves.map(parse)
  const fill = halves.length === 2 ? Array<number>(8 - left.length - right.length).fill(0) : []
  const all = [...left, ...fill, ...right]
  return all.length === 8 && all.every(group => Number.isInteger(group) && group >= 0 && group <= 0xffff) ? all : undefined
}

const publicV6 = (all: number[]) => {
  const [g0 = 0, g1 = 0, g2 = 0, g3 = 0, g4 = 0, g5 = 0, g6 = 0, g7 = 0] = all
  // An IPv4 address carried in IPv6, mapped (::ffff:0:0/96) or translated (64:ff9b::/96), is judged as itself.
  if ((!g0 && !g1 && !g2 && !g3 && !g4 && g5 === 0xffff) || (g0 === 0x64 && g1 === 0xff9b && !g2 && !g3 && !g4 && !g5)) {
    return publicV4([g6 >> 8, g6 & 255, g7 >> 8])
  }
  if (all.every(group => group === 0) || (all.slice(0, 7).every(group => group === 0) && g7 === 1)) return false
  // Unique local fc00::/7, link-local fe80::/10, multicast ff00::/8, documentation 2001:db8::/32, ORCHID and Teredo.
  return !(
    (g0 & 0xfe00) === 0xfc00 ||
    (g0 & 0xffc0) === 0xfe80 ||
    (g0 & 0xff00) === 0xff00 ||
    (g0 === 0x2001 && (g1 === 0xdb8 || g1 < 0x200))
  )
}

/** Whether an address is one a URL a client chose may reach: none of RFC 6890's special-use ranges. */
export const isPublicAddress = (address: string) => {
  const literal = address.replace(/^\[|\]$/g, '').split('%')[0] as string
  const v4 = octets(literal)
  if (v4) return publicV4(v4)
  const v6 = literal.includes(':') ? groups(literal.toLowerCase()) : undefined
  return v6 ? publicV6(v6) : false
}

export type SafeFetchOptions = {
  /** Bytes of body read before the fetch is refused. @default 65536 */
  maxBytes?: number
  /** Milliseconds before it is abandoned. @default 5000 */
  timeoutMs?: number
}

export type SafeFetch = (input: string | URL, init?: RequestInit & SafeFetchOptions) => Promise<Response>

export type SafeFetchRuntime = {
  /** The addresses a name resolves to; omitted where the runtime cannot resolve one, and then names are not checked. */
  resolve?: (hostname: string) => Promise<string[]>
  /** The request, sent to one of `addresses` where the runtime can choose the address, without following a redirect. */
  send: (url: URL, init: RequestInit, addresses: string[]) => Promise<Response>
}

/** Reads at most `limit` bytes, and refuses a longer body without reading it to its end. */
const capped = async (url: string, response: Response, limit: number) => {
  const reader = response.body?.getReader()
  const chunks: Uint8Array[] = []
  let size = 0
  for (;;) {
    const read = await reader?.read()
    if (!read || read.done) break
    size += read.value.byteLength
    if (size > limit) {
      await reader?.cancel()
      throw new UnsafeFetchError(url, `its body is over ${limit} bytes`)
    }
    chunks.push(read.value)
  }
  const body = new Uint8Array(size)
  let at = 0
  for (const chunk of chunks) {
    body.set(chunk, at)
    at += chunk.byteLength
  }
  return new Response(body, { status: response.status, statusText: response.statusText, headers: response.headers })
}

/**
 * `fetch` for a URL a client chose (NFR-S14): https only, every address the name resolves to public, no redirect followed,
 * a deadline and a cap on the body. The provider builds none of this into its own requests, which it does not make (FR-A1):
 * each runtime entry exports one, as `safeFetch`, for the host's `resolveClientMetadata` and deliveries.
 */
export const createSafeFetch =
  ({ resolve, send }: SafeFetchRuntime): SafeFetch =>
  async (input, { maxBytes = 65_536, timeoutMs = 5_000, ...init } = {}) => {
    const url = new URL(input)
    if (url.protocol !== 'https:') throw new UnsafeFetchError(url.href, 'it is not https')
    if (url.username || url.password) throw new UnsafeFetchError(url.href, 'it carries credentials')
    const host = url.hostname.replace(/^\[|\]$/g, '')
    const literal = Boolean(octets(host)) || host.includes(':')
    const addresses = literal ? [host] : resolve ? await resolve(host) : []
    if ((literal || resolve) && (!addresses.length || !addresses.every(isPublicAddress))) {
      throw new UnsafeFetchError(url.href, `${host} is not a public address`)
    }
    const signal = init.signal ? AbortSignal.any([init.signal, AbortSignal.timeout(timeoutMs)]) : AbortSignal.timeout(timeoutMs)
    const response = await send(url, { ...init, redirect: 'manual', signal }, addresses)
    // A redirect would take the request somewhere no check above was made of.
    if (response.status >= 300 && response.status < 400) throw new UnsafeFetchError(url.href, `it redirects (${response.status})`)
    return capped(url.href, response, maxBytes)
  }
