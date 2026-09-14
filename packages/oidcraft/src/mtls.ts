import type { ClientCertificate } from './context'
import { base64url } from './random'
import type { Client } from './types'

/** RFC 8705 §3.1: the SHA-256 thumbprint of the DER certificate, base64url. */
export const certificateThumbprint = async (der: Uint8Array) =>
  base64url(new Uint8Array(await crypto.subtle.digest('SHA-256', der as unknown as ArrayBuffer)))

/**
 * `tls_client_auth` (RFC 8705 §2.1): the client is whoever holds a certificate whose subject the
 * provider has on record. The certificate must already be *verified* by the listener — this checks
 * identity, not trust, and the two are only equivalent when the host terminates TLS properly (FR-R4).
 */
export const matchesSubjectDn = (client: Client, certificate: ClientCertificate) =>
  Boolean(client.tlsClientAuthSubjectDn && certificate.subjectDn && client.tlsClientAuthSubjectDn === certificate.subjectDn)

/**
 * `self_signed_tls_client_auth` (RFC 8705 §2.2): no chain to check, so identity rests entirely on
 * the certificate matching one the client registered.
 */
export const matchesRegisteredCertificate = async (client: Client, certificate: ClientCertificate) => {
  const registered = (client.jwks?.keys as { 'x5t#S256'?: string }[] | undefined) ?? []
  if (!registered.length) return false
  const thumbprint = await certificateThumbprint(certificate.der)
  return registered.some(key => key['x5t#S256'] === thumbprint)
}
