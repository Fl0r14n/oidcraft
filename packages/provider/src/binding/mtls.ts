import { base64url } from 'jose'
import type { ClientCertificate } from '../context'
import type { Client } from '../types'

/** RFC 8705 §3.1: the SHA-256 thumbprint of the DER certificate, base64url. */
export const certificateThumbprint = async (der: Uint8Array) =>
  base64url.encode(new Uint8Array(await crypto.subtle.digest('SHA-256', der as unknown as ArrayBuffer)))

/** Attribute types written more than one way — short name, long name, OID — mapped to one. */
const ATTRIBUTE_TYPES: Record<string, string> = {
  '2.5.4.3': 'cn',
  commonname: 'cn',
  '2.5.4.5': 'serialnumber',
  '2.5.4.6': 'c',
  countryname: 'c',
  '2.5.4.7': 'l',
  localityname: 'l',
  '2.5.4.8': 'st',
  stateorprovincename: 'st',
  s: 'st',
  '2.5.4.9': 'street',
  streetaddress: 'street',
  '2.5.4.10': 'o',
  organizationname: 'o',
  '2.5.4.11': 'ou',
  organizationalunitname: 'ou',
  '0.9.2342.19200300.100.1.1': 'uid',
  userid: 'uid',
  '0.9.2342.19200300.100.1.25': 'dc',
  domaincomponent: 'dc',
  '1.2.840.113549.1.9.1': 'emailaddress',
  email: 'emailaddress',
  e: 'emailaddress'
}

const SPECIAL = new Set([',', '+', '"', '\\', '<', '>', ';', '=', '#', ' '])

/**
 * An RFC 4514 distinguished name as its RDNs, most specific first, each a sorted list of
 * `type=value` with the type in one spelling and the value case-folded and its spaces collapsed —
 * the comparison RFC 4517 §4.2.15 `distinguishedNameMatch` makes. Undefined when it does not parse.
 */
export const parseDistinguishedName = (dn: string) => {
  const rdns: string[][] = []
  let rdn: string[] = []
  let type = ''
  let bytes: number[] = []
  let kept = 0
  let readingValue = false
  const encoder = new TextEncoder()
  const flush = () => {
    const name = type.trim().toLowerCase()
    if (!name) return false
    const raw = new TextDecoder().decode(new Uint8Array(bytes.slice(0, kept)))
    const value = raw.startsWith('#') ? raw.toLowerCase() : raw.toLowerCase().replace(/\s+/g, ' ').trim()
    rdn.push(`${ATTRIBUTE_TYPES[name] ?? name}=${value}`)
    type = ''
    bytes = []
    kept = 0
    readingValue = false
    return true
  }
  for (let index = 0; index < dn.length; index++) {
    const char = dn[index] as string
    if (!readingValue) {
      if (char === '=') readingValue = true
      else if (char === ',' || char === '+' || char === '\\') return undefined
      else type += char
      continue
    }
    if (char === '\\') {
      const next = dn[index + 1]
      const pair = dn.slice(index + 1, index + 3)
      if (/^[0-9a-fA-F]{2}$/.test(pair)) {
        bytes.push(Number.parseInt(pair, 16))
        index += 2
      } else if (next !== undefined && SPECIAL.has(next)) {
        bytes.push(...encoder.encode(next))
        index += 1
      } else return undefined
      kept = bytes.length
      continue
    }
    if (char === ',' || char === ';' || char === '+') {
      if (!flush()) return undefined
      if (char !== '+') {
        rdns.push(rdn.sort())
        rdn = []
      }
      continue
    }
    if (char === ' ' && bytes.length === 0) continue
    bytes.push(...encoder.encode(char))
    if (char !== ' ') kept = bytes.length
  }
  if (!readingValue || !flush()) return undefined
  rdns.push(rdn.sort())
  return rdns
}

const sameDistinguishedName = (a: string, b: string) => {
  const left = parseDistinguishedName(a)
  const right = parseDistinguishedName(b)
  return Boolean(left && right && JSON.stringify(left) === JSON.stringify(right))
}

/**
 * `tls_client_auth` (RFC 8705 §2.1): the client is whoever holds a certificate, issued by a CA the
 * listener trusts, whose subject matches the one on record — compared as names, not strings
 * (RFC 8705 §2.1.2). An unverified certificate never qualifies: only the chain makes its subject
 * mean anything (FR-R4).
 */
export const matchesSubjectDn = (client: Client, certificate: ClientCertificate) =>
  Boolean(
    certificate.verified &&
      client.tlsClientAuthSubjectDn &&
      certificate.subjectDn &&
      sameDistinguishedName(client.tlsClientAuthSubjectDn, certificate.subjectDn)
  )

/**
 * `self_signed_tls_client_auth` (RFC 8705 §2.2): no chain to check, so identity rests entirely on
 * the certificate matching one the client registered. A `verified` flag is irrelevant here: the TLS
 * handshake already proved the client holds that certificate's private key.
 */
export const matchesRegisteredCertificate = (client: Client, certificate: ClientCertificate) => {
  const registered = (client.jwks?.keys as { 'x5t#S256'?: string }[] | undefined) ?? []
  if (!registered.length) return false
  return registered.some(key => key['x5t#S256'] === certificate.thumbprint)
}
