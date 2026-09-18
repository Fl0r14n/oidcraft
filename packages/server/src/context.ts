import type { Client } from './types'

/**
 * What a WHATWG `Request` cannot carry, supplied by the host (FR-R4).
 *
 * Every one of these is runtime-specific, which is why each runtime gets its own tiny entry —
 * `oidcraft/runtimes/{bun,deno,node,workerd}` — rather than the core
 * sniffing for globals or trusting a header.
 */
export type RequestContext = {
  /** The deployment's public origin. Configuration, never derived from a header (NFR-S6). */
  issuer: string
  /** The peer address. Not available from `Request` on any runtime. */
  clientIp?: string | undefined
  /**
   * The verified client certificate, when the listener requested one. Required by the mTLS client
   * authentication methods (FR-C4) and certificate-bound tokens (FR-C13); those methods are
   * unavailable without it.
   */
  clientCertificate?: ClientCertificate | undefined
}

/** DER bytes plus the fields RFC 8705 matches on. The core never parses X.509 itself. */
export type ClientCertificate = {
  der: Uint8Array
  subjectDn?: string | undefined
  issuerDn?: string | undefined
  sanDnsNames?: string[] | undefined
  sanUris?: string[] | undefined
}

/** Builds the context for one request. Each runtime entry exports one of these. */
export type ContextProvider<TExtra = unknown> = (request: Request, extra: TExtra) => RequestContext

export type ClientAuthenticationInput = {
  client: Client
  context: RequestContext
}
