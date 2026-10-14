import { argon2, createHash, randomBytes, timingSafeEqual } from 'node:crypto'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { Readable } from 'node:stream'
import type { ClientCertificate, RequestContext } from 'oidcraft'

export type NodeBridgeOptions = {
  /** Trust `X-Forwarded-*`. Off by default: believing it unconditionally forges the issuer (NFR-S6). */
  trustProxy?: boolean
}

type TlsSocket = {
  remoteAddress?: string | undefined
  encrypted?: boolean
  getPeerCertificate?: (detailed?: boolean) => { raw?: Uint8Array; subject?: unknown; issuer?: unknown }
  authorized?: boolean
}

const socketOf = (request: IncomingMessage) => request.socket as unknown as TlsSocket

const peerCertificate = (socket: TlsSocket): ClientCertificate | undefined => {
  // An unverified certificate is a claim, not an identity: only `authorized` means the chain checked.
  if (!socket.authorized || !socket.getPeerCertificate) return undefined
  const raw = socket.getPeerCertificate(true).raw
  return raw ? { thumbprint: createHash('sha256').update(raw).digest('base64url') } : undefined
}

/**
 * The address the trusted proxy saw is the one it appended: the right-most. Everything to its left
 * arrived from the client and is whatever the client chose to write (NFR-S6).
 */
const forwardedIp = (request: IncomingMessage) => {
  const header = request.headers['x-forwarded-for']
  const last = (Array.isArray(header) ? header.join(',') : header)?.split(',').at(-1)?.trim()
  return last || undefined
}

/**
 * The context for one request. `trustProxy` is opt-in because `X-Forwarded-For` is attacker-supplied
 * unless a proxy you control is the only thing that can reach this process (FR-R4, NFR-S6).
 */
export const nodeContext =
  (issuer: string, options: NodeBridgeOptions = {}) =>
  (request: IncomingMessage): RequestContext => {
    const socket = socketOf(request)
    const clientIp = (options.trustProxy ? forwardedIp(request) : undefined) ?? socket.remoteAddress
    const certificate = peerCertificate(socket)
    return { issuer, ...(clientIp && { clientIp }), ...(certificate && { clientCertificate: certificate }) }
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
  const context = nodeContext(issuer, options)
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

/**
 * argon2id through `node:crypto` (Node ≥ 24.7), for `oidcraft/accounts` (FR-I7). PHC strings, so the
 * hashes the Bun entry's hasher writes verify here and the other way round.
 */
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
