import type { ClientCertificate, RequestContext } from 'oidcraft'

export type NodeBridgeOptions = {
  /** Trust `X-Forwarded-*`. Off by default: believing it unconditionally forges the issuer (NFR-S6). */
  trustProxy?: boolean
}

type TlsSocket = {
  remoteAddress?: string
  getPeerCertificate?: (detailed?: boolean) => { raw?: Uint8Array; subject?: unknown; issuer?: unknown }
  authorized?: boolean
}

/**
 * The one runtime that needs an HTTP bridge: `node:http` speaks `IncomingMessage`/`ServerResponse`,
 * not `Request`/`Response` (FR-R3). The conversion and this context provider live here together
 * because they are the same seam.
 */
export const nodeContext =
  (issuer: string) =>
  (_request: Request, socket: TlsSocket): RequestContext => ({
    issuer,
    clientIp: socket.remoteAddress,
    clientCertificate: peerCertificate(socket)
  })

const peerCertificate = (socket: TlsSocket): ClientCertificate | undefined => {
  if (!socket.authorized || !socket.getPeerCertificate) return undefined
  const raw = socket.getPeerCertificate(true).raw
  return raw ? { der: raw } : undefined
}
