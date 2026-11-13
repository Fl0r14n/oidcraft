import { describe, expect, test } from 'bun:test'
import type { Client } from '@oidcraft/adapter'
import { matchesRegisteredCertificate, matchesTlsClientAuth, parseDistinguishedName } from './mtls'

const client = (over: Partial<Client> = {}) => ({ clientId: 'rp', ...over }) as Client

describe('distinguished names compare as names, not strings (RFC 8705 §2.1.2, RFC 4517 §4.2.15)', () => {
  const same = (a: string, b: string) =>
    matchesTlsClientAuth(client({ tlsClientAuthSubjectDn: a }), { thumbprint: 't', verified: true, subjectDn: b })

  test('spacing, case and the spelling of an attribute type do not matter', () => {
    expect(same('CN=rp,O=Acme,C=US', 'cn=RP, o = acme ,  c=us')).toBe(true)
    expect(same('CN=rp,O=Acme', 'commonName=rp,organizationName=Acme')).toBe(true)
    expect(same('CN=rp,O=Acme', '2.5.4.3=rp,2.5.4.10=Acme')).toBe(true)
    expect(same('CN=Relying  Party', 'CN=relying party')).toBe(true)
  })

  test('an escaped comma is part of the value, in either escape form', () => {
    expect(same('CN=rp,O=Acme\\, Inc.,C=US', 'CN=rp,O=Acme\\2C Inc.,C=US')).toBe(true)
    expect(same('CN=rp,O=Acme\\, Inc.,C=US', 'CN=rp,O=Acme,O=Inc.,C=US')).toBe(false)
  })

  test('the order of RDNs matters; the order inside a multi-valued RDN does not', () => {
    expect(same('CN=rp,O=Acme', 'O=Acme,CN=rp')).toBe(false)
    expect(same('CN=rp+UID=7,O=Acme', 'UID=7+CN=rp,O=Acme')).toBe(true)
  })

  test('a different value, a missing RDN or an unparseable name never matches', () => {
    expect(same('CN=rp,O=Acme', 'CN=rp,O=Other')).toBe(false)
    expect(same('CN=rp,O=Acme', 'CN=rp')).toBe(false)
    expect(same('CN=rp', 'CN=rp\\')).toBe(false)
    expect(parseDistinguishedName('no equals sign')).toBeUndefined()
    expect(parseDistinguishedName('=rp')).toBeUndefined()
  })
})

describe('what verification each method needs (RFC 8705 §2)', () => {
  const registered = client({ tlsClientAuthSubjectDn: 'CN=rp', jwks: { keys: [{ 'x5t#S256': 'thumb' }] } })

  test('tls_client_auth refuses an unverified certificate, however well its subject matches', () => {
    expect(matchesTlsClientAuth(registered, { thumbprint: 'thumb', verified: true, subjectDn: 'CN=rp' })).toBe(true)
    expect(matchesTlsClientAuth(registered, { thumbprint: 'thumb', verified: false, subjectDn: 'CN=rp' })).toBe(false)
  })

  test('self_signed_tls_client_auth matches the registered certificate whether or not a CA verified it', () => {
    expect(matchesRegisteredCertificate(registered, { thumbprint: 'thumb', verified: false })).toBe(true)
    expect(matchesRegisteredCertificate(registered, { thumbprint: 'other', verified: false })).toBe(false)
  })
})

describe('a SAN registered for tls_client_auth (RFC 8705 §2.1.2)', () => {
  const certificate = {
    thumbprint: 't',
    verified: true,
    subjectDn: 'CN=rp',
    sanDnsNames: ['RP.Example.COM'],
    sanUris: ['https://rp.example.com/clients/a,b'],
    sanIps: ['2001:DB8:0:0:0:0:0:1', '192.0.2.7'],
    sanEmails: ['Ops@Example.COM']
  }
  const matches = (over: Partial<Client>) => matchesTlsClientAuth(client(over), certificate)

  test('a DNS name, case-insensitively', () => {
    expect(matches({ tlsClientAuthSanDns: 'rp.example.com' })).toBe(true)
    expect(matches({ tlsClientAuthSanDns: 'other.example.com' })).toBe(false)
  })

  test('a URI, exactly', () => {
    expect(matches({ tlsClientAuthSanUri: 'https://rp.example.com/clients/a,b' })).toBe(true)
    expect(matches({ tlsClientAuthSanUri: 'https://rp.example.com/Clients/a,b' })).toBe(false)
  })

  test('an IP address, whatever its spelling', () => {
    expect(matches({ tlsClientAuthSanIp: '2001:db8::1' })).toBe(true)
    expect(matches({ tlsClientAuthSanIp: '2001:0db8:0000::0001' })).toBe(true)
    expect(matches({ tlsClientAuthSanIp: '192.0.2.7' })).toBe(true)
    expect(matches({ tlsClientAuthSanIp: '2001:db8::2' })).toBe(false)
    expect(matches({ tlsClientAuthSanIp: 'rp.example.com' })).toBe(false)
  })

  test('an email address: the domain case-insensitively, the local part exactly', () => {
    expect(matches({ tlsClientAuthSanEmail: 'Ops@example.com' })).toBe(true)
    expect(matches({ tlsClientAuthSanEmail: 'ops@Example.COM' })).toBe(false)
  })

  test('only on a verified certificate, and only with exactly one name on record', () => {
    expect(matchesTlsClientAuth(client({ tlsClientAuthSanDns: 'rp.example.com' }), { ...certificate, verified: false })).toBe(false)
    expect(matches({ tlsClientAuthSanDns: 'rp.example.com', tlsClientAuthSubjectDn: 'CN=rp' })).toBe(false)
    expect(matches({})).toBe(false)
  })
})
