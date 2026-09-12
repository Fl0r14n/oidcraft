export type NodeBridgeOptions = {
  /** Trust `X-Forwarded-*`. Off by default: believing it unconditionally forges the issuer (NFR-S6). */
  trustProxy?: boolean
}
