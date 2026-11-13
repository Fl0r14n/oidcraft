import type { Client } from '@oidcraft/adapter'
import { base64url } from 'jose'
import type { ClientCertificate } from '../context'

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

// RFC 4517 §4.2.15 `distinguishedNameMatch`: types in one spelling, values case-folded with spaces collapsed.
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

/** RFC 8705 §2.1.2: a `tls_client_auth` client registers exactly one of these. */
export const TLS_CLIENT_AUTH_NAMES = [
  'tlsClientAuthSubjectDn',
  'tlsClientAuthSanDns',
  'tlsClientAuthSanUri',
  'tlsClientAuthSanIp',
  'tlsClientAuthSanEmail'
] as const

export const registeredNames = (client: Client) => TLS_CLIENT_AUTH_NAMES.filter(name => client[name] !== undefined)

/** One IPv6 address has many spellings; a URL host has one (RFC 5952). Undefined for anything not an IP literal. */
export const canonicalIp = (ip: string) => {
  const host = ip.includes(':') ? `[${ip}]` : ip
  if (!/^(\d{1,3}(\.\d{1,3}){3}|\[[0-9a-fA-F:.]+\])$/.test(host)) return undefined
  return URL.canParse(`http://${host}/`) ? new URL(`http://${host}/`).hostname : undefined
}

/** RFC 5321 §2.4: the domain is case-insensitive, the local part is the recipient's to interpret. */
const sameEmail = (a: string, b: string) => {
  const [localA, domainA] = [a.slice(0, a.lastIndexOf('@')), a.slice(a.lastIndexOf('@') + 1)]
  const [localB, domainB] = [b.slice(0, b.lastIndexOf('@')), b.slice(b.lastIndexOf('@') + 1)]
  return a.includes('@') && localA === localB && domainA.toLowerCase() === domainB.toLowerCase()
}

const carries = (values: string[] | undefined, registered: string, same: (a: string, b: string) => boolean) =>
  (values ?? []).some(value => same(value, registered))

// RFC 8705 §2.1: only a verified chain makes a name mean anything (FR-R4), and the client must have exactly one on record.
export const matchesTlsClientAuth = (client: Client, certificate: ClientCertificate) => {
  const [name, ...others] = registeredNames(client)
  const registered = name && client[name]
  if (!certificate.verified || !registered || others.length) return false
  switch (name) {
    case 'tlsClientAuthSubjectDn':
      return Boolean(certificate.subjectDn && sameDistinguishedName(registered, certificate.subjectDn))
    case 'tlsClientAuthSanDns':
      return carries(certificate.sanDnsNames, registered, (a, b) => a.toLowerCase() === b.toLowerCase())
    case 'tlsClientAuthSanUri':
      return carries(certificate.sanUris, registered, (a, b) => a === b)
    case 'tlsClientAuthSanIp':
      return carries(certificate.sanIps, registered, (a, b) => canonicalIp(a) !== undefined && canonicalIp(a) === canonicalIp(b))
    case 'tlsClientAuthSanEmail':
      return carries(certificate.sanEmails, registered, sameEmail)
  }
}

// RFC 8705 §2.2: `verified` is irrelevant; the handshake proved the key, and only a registered certificate matches.
export const matchesRegisteredCertificate = (client: Client, certificate: ClientCertificate) => {
  const registered = (client.jwks?.keys as { 'x5t#S256'?: string }[] | undefined) ?? []
  if (!registered.length) return false
  return registered.some(key => key['x5t#S256'] === certificate.thumbprint)
}
