import { type ClientCertificate, createSafeFetch, type RequestContext } from '@oidcraft/provider'

/** The part of Cloudflare's `request.cf` this entry reads. */
export type IncomingCf = {
  tlsClientAuth?: {
    certPresented?: string
    certVerified?: string
    certSubjectDN?: string
    certIssuerDN?: string
    certFingerprintSHA256?: string
  }
}

const hexToBase64url = (hex: string) =>
  btoa(String.fromCharCode(...(hex.match(/../g) ?? []).map(byte => Number.parseInt(byte, 16))))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')

const certificate = (cf: IncomingCf): ClientCertificate | undefined => {
  const auth = cf.tlsClientAuth
  // "SUCCESS" is the only value that means the edge verified it; anything else is an unverified claim.
  if (auth?.certPresented !== '1' || auth.certVerified !== 'SUCCESS') return undefined
  // Workers never see the DER, only its hex SHA-256; without it every client would share one thumbprint (FR-C13).
  const fingerprint = auth.certFingerprintSHA256
  if (!fingerprint || !/^[0-9a-f]{64}$/i.test(fingerprint)) return undefined
  return { thumbprint: hexToBase64url(fingerprint), verified: true, subjectDn: auth.certSubjectDN, issuerDn: auth.certIssuerDN }
}

/** Cloudflare puts the peer address in a header and the verified client certificate on `request.cf`. */
export const workerdContext = (request: Request, cf: IncomingCf = {}): RequestContext => ({
  clientIp: request.headers.get('cf-connecting-ip') ?? undefined,
  clientCertificate: certificate(cf)
})

/**
 * `fetch` for a URL a client chose (NFR-S14), within a deadline and a cap on the body. A Worker cannot resolve a name, so
 * names are not checked here; an address literal still is, and Cloudflare's own fetch does not reach a private network.
 */
export const safeFetch = createSafeFetch({ send: (url, init) => fetch(url, init) })
