/**
 * What a WHATWG `Request` cannot carry, from each runtime's own `@oidcraft/provider/runtimes/*` entry (FR-R4).
 * Never the issuer: that is configuration, not a property of a request (NFR-S6).
 */
export type RequestContext = {
  /** The peer address. `handle` does not read it; it is for the host's own limits, such as device codes per address (FR-R4, NFR-S12). */
  clientIp?: string | undefined
  /** The client certificate, when the listener requested one; mTLS client auth (FR-C4) and bound tokens (FR-C13) need it. */
  clientCertificate?: ClientCertificate | undefined
}

/** The fields RFC 8705 matches on. The core never parses X.509 itself. */
export type ClientCertificate = {
  /** `x5t#S256`: the base64url SHA-256 of the DER certificate (RFC 8705 §3.1). `certificateThumbprint` computes it. */
  thumbprint: string
  /**
   * Whether the listener verified the chain to a CA it trusts. `tls_client_auth` requires it; self-signed
   * auth and bound tokens do not, as the handshake already proved possession of the key (RFC 8705 §2.2, §3).
   */
  verified: boolean
  /** RFC 4514, most specific first, as `tls_client_auth_subject_dn` is registered. Compared as a name, not a string. */
  subjectDn?: string | undefined
  issuerDn?: string | undefined
  sanDnsNames?: string[] | undefined
  sanUris?: string[] | undefined
  sanIps?: string[] | undefined
  sanEmails?: string[] | undefined
}

/** Builds the context for one request. Each runtime entry exports one of these. */
export type ContextProvider<TExtra = unknown> = (request: Request, extra: TExtra) => RequestContext
