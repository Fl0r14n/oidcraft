import type { Client } from '@oidcraft/adapter'

/**
 * What a WHATWG `Request` cannot carry, supplied by the host (FR-R4). The issuer is not among them:
 * it is configuration, never a property of a request (NFR-S6).
 *
 * Every one of these is runtime-specific, which is why each runtime gets its own tiny entry —
 * `@oidcraft/provider/runtimes/{bun,deno,node,workerd}` — rather than the core
 * sniffing for globals or trusting a header.
 */
export type RequestContext = {
  /**
   * The peer address. Not available from `Request` on any runtime. `handle` does not read it: it is
   * for the limits the host applies with it, such as wrong device codes per address (FR-R4, NFR-S12).
   */
  clientIp?: string | undefined
  /**
   * The verified client certificate, when the listener requested one. Required by the mTLS client
   * authentication methods (FR-C4) and certificate-bound tokens (FR-C13); those methods are
   * unavailable without it.
   */
  clientCertificate?: ClientCertificate | undefined
}

/** The fields RFC 8705 matches on. The core never parses X.509 itself. */
export type ClientCertificate = {
  /** `x5t#S256`: the base64url SHA-256 of the DER certificate (RFC 8705 §3.1). `certificateThumbprint` computes it. */
  thumbprint: string
  /**
   * Whether the TLS listener verified the chain to a CA it trusts. `tls_client_auth` requires it;
   * `self_signed_tls_client_auth` and certificate-bound tokens do not, because the handshake
   * already proved possession of the key (RFC 8705 §2.2, §3).
   */
  verified: boolean
  /** RFC 4514, most specific first, as `tls_client_auth_subject_dn` is registered. Compared as a name, not a string. */
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
