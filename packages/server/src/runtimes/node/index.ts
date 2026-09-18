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
  return raw ? { der: raw } : undefined
}

const forwardedIp = (request: IncomingMessage) => {
  const header = request.headers['x-forwarded-for']
  const first = (Array.isArray(header) ? header[0] : header)?.split(',')[0]?.trim()
  return first || undefined
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
