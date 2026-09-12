import type { ClientCertificate, RequestContext } from 'oidcraft'

type IncomingCf = {
  tlsClientAuth?: { certPresented?: string; certVerified?: string; certSubjectDN?: string; certIssuerDN?: string }
}

const certificate = (cf: IncomingCf): ClientCertificate | undefined => {
  const auth = cf.tlsClientAuth
  // "SUCCESS" is the only value that means the edge verified it; anything else is an unverified claim.
  if (auth?.certPresented !== '1' || auth.certVerified !== 'SUCCESS') return undefined
  return { der: new Uint8Array(), subjectDn: auth.certSubjectDN, issuerDn: auth.certIssuerDN }
}

/** Cloudflare puts the peer address in a header and the verified client certificate on `request.cf`. */
export const workerdContext =
  (issuer: string) =>
  (request: Request, cf: IncomingCf = {}): RequestContext => ({
    issuer,
    clientIp: request.headers.get('cf-connecting-ip') ?? undefined,
    clientCertificate: certificate(cf)
  })
