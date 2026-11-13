import { argon2, createHash, randomBytes, timingSafeEqual, X509Certificate } from 'node:crypto'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { Readable } from 'node:stream'
import type { ClientCertificate, RequestContext } from '@oidcraft/provider'

export type NodeBridgeOptions = {
  /** Take the client IP from the right-most `X-Forwarded-For` hop, only when your proxy is the only route in (FR-R4, NFR-S6). */
  trustProxy?: boolean
}

type TlsSocket = {
  remoteAddress?: string | undefined
  encrypted?: boolean
  getPeerCertificate?: (detailed?: boolean) => { raw?: Uint8Array; subject?: unknown; issuer?: unknown }
  authorized?: boolean
}

const socketOf = (request: IncomingMessage) => request.socket as unknown as TlsSocket

/** OpenSSL prints a name one RDN per line, most general first and RFC 2253-escaped; RFC 4514 wants it reversed on one line. */
const distinguishedName = (printed: string) => printed.split('\n').filter(Boolean).reverse().join(',')

// A value holding a comma is printed JSON-quoted, so the text is read entry by entry rather than split.
export const subjectAltNames = (text: string | undefined) => {
  const entries: [string, string][] = []
  let at = 0
  while (text && at < text.length) {
    const colon = text.indexOf(':', at)
    if (colon < 0) break
    const type = text.slice(at, colon).trim()
    let end = colon + 1
    let value: string
    if (text[end] === '"') {
      let close = end + 1
      while (close < text.length && text[close] !== '"') close += text[close] === '\\' ? 2 : 1
      value = JSON.parse(text.slice(end, close + 1))
      end = close + 1
    } else {
      const next = text.indexOf(', ', end)
      value = next < 0 ? text.slice(end) : text.slice(end, next)
      end = next < 0 ? text.length : next
    }
    entries.push([type, value])
    at = text.startsWith(', ', end) ? end + 2 : end
  }
  return entries
}

const SAN_FIELDS: Record<string, 'sanDnsNames' | 'sanUris' | 'sanIps' | 'sanEmails'> = {
  DNS: 'sanDnsNames',
  URI: 'sanUris',
  'IP Address': 'sanIps',
  email: 'sanEmails'
}

const sansOf = (x509: X509Certificate) => {
  const sans: Partial<Record<'sanDnsNames' | 'sanUris' | 'sanIps' | 'sanEmails', string[]>> = {}
  for (const [type, value] of subjectAltNames(x509.subjectAltName)) {
    const field = SAN_FIELDS[type]
    if (field) sans[field] = [...(sans[field] ?? []), value]
  }
  return sans
}

const peerCertificate = (socket: TlsSocket): ClientCertificate | undefined => {
  const raw = socket.getPeerCertificate?.(true).raw
  if (!raw?.length) return undefined
  const x509 = new X509Certificate(raw)
  return {
    thumbprint: createHash('sha256').update(raw).digest('base64url'),
    // Only `authorized` means the chain checked; an unverified certificate still proves its key (RFC 8705 §2.2).
    verified: socket.authorized === true,
    subjectDn: distinguishedName(x509.subject),
    issuerDn: distinguishedName(x509.issuer),
    ...sansOf(x509)
  }
}

// The trusted proxy appended the right-most hop; everything left of it is whatever the client wrote (NFR-S6).
const forwardedIp = (request: IncomingMessage) => {
  const header = request.headers['x-forwarded-for']
  const last = (Array.isArray(header) ? header.join(',') : header)?.split(',').at(-1)?.trim()
  return last || undefined
}

/** The context for one request. `trustProxy` is opt-in: `X-Forwarded-For` is attacker-supplied (FR-R4, NFR-S6). */
export const nodeContext =
  (options: NodeBridgeOptions = {}) =>
  (request: IncomingMessage): RequestContext => {
    const socket = socketOf(request)
    const clientIp = (options.trustProxy ? forwardedIp(request) : undefined) ?? socket.remoteAddress
    const certificate = peerCertificate(socket)
    return { ...(clientIp && { clientIp }), ...(certificate && { clientCertificate: certificate }) }
  }

/** `node:http` speaks IncomingMessage/ServerResponse; this is the only runtime needing that translated (FR-R3). */
export const toRequest = (incoming: IncomingMessage, issuer: string) => {
  const url = new URL(incoming.url ?? '/', issuer)
  const headers = new Headers()
  for (const [name, value] of Object.entries(incoming.headers)) {
    if (value === undefined) continue
    for (const single of Array.isArray(value) ? value : [value]) headers.append(name, single)
  }

  const method = incoming.method ?? 'GET'
  const hasBody = method !== 'GET' && method !== 'HEAD'
  return new Request(url, {
    method,
    headers,
    ...(hasBody && { body: Readable.toWeb(incoming) as unknown as ReadableStream, duplex: 'half' })
  } as RequestInit)
}

export const sendResponse = async (response: Response, outgoing: ServerResponse) => {
  outgoing.statusCode = response.status
  for (const [name, value] of response.headers) {
    // set-cookie is the one header that may legitimately repeat; Headers joins it with ", ".
    if (name === 'set-cookie') outgoing.appendHeader?.(name, value)
    else outgoing.setHeader(name, value)
  }
  if (!response.body) {
    outgoing.end()
    return
  }
  for await (const chunk of response.body as unknown as AsyncIterable<Uint8Array>) outgoing.write(chunk)
  outgoing.end()
}

export type NodeHandler = (incoming: IncomingMessage, outgoing: ServerResponse) => Promise<void>

/** Mounts a provider on a node:http server, an Express app, or anything with that signature. */
export const toNodeHandler = (
  handle: (request: Request, context: RequestContext) => Promise<Response>,
  issuer: string,
  options: NodeBridgeOptions = {}
): NodeHandler => {
  const context = nodeContext(options)
  return async (incoming, outgoing) => {
    const response = await handle(toRequest(incoming, issuer), context(incoming))
    await sendResponse(response, outgoing)
  }
}

/** RFC 9106 §4's second recommended setting: 64 MiB, three passes, four lanes. */
const ARGON2 = { memory: 65536, passes: 3, parallelism: 4, tagLength: 32 }

const derive = (password: string, nonce: Buffer, params: typeof ARGON2) =>
  new Promise<Buffer>((resolve, reject) => {
    argon2('argon2id', { message: password, nonce, ...params }, (error, key) => (error ? reject(error) : resolve(key)))
  })

const PHC = /^\$argon2id\$v=19\$m=(\d+),t=(\d+),p=(\d+)\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)$/

/** argon2id through `node:crypto`, for `@oidcraft/provider/accounts` (FR-I7); its PHC strings verify under the Bun entry's too. */
export const nodePasswordHasher = {
  async hash(password: string) {
    const nonce = randomBytes(16)
    const key = await derive(password, nonce, ARGON2)
    const b64 = (buffer: Buffer) => buffer.toString('base64').replace(/=+$/, '')
    return `$argon2id$v=19$m=${ARGON2.memory},t=${ARGON2.passes},p=${ARGON2.parallelism}$${b64(nonce)}$${b64(key)}`
  },
  async verify(password: string, hash: string) {
    const match = PHC.exec(hash)
    if (!match) return false
    const [, memory, passes, parallelism, nonce, expected] = match as unknown as string[]
    const target = Buffer.from(expected as string, 'base64')
    const params = { memory: Number(memory), passes: Number(passes), parallelism: Number(parallelism), tagLength: target.length }
    const key = await derive(password, Buffer.from(nonce as string, 'base64'), params)
    return key.length === target.length && timingSafeEqual(key, target)
  }
}
