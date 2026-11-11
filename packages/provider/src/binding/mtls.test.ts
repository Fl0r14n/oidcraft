import { describe, expect, test } from 'bun:test'
import type { Client } from '@oidcraft/adapter'
import { matchesRegisteredCertificate, matchesSubjectDn, parseDistinguishedName } from './mtls'

const client = (over: Partial<Client> = {}) => ({ clientId: 'rp', ...over }) as Client

describe('distinguished names compare as names, not strings (RFC 8705 §2.1.2, RFC 4517 §4.2.15)', () => {
  const same = (a: string, b: string) =>
    matchesSubjectDn(client({ tlsClientAuthSubjectDn: a }), { thumbprint: 't', verified: true, subjectDn: b })

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
    expect(matchesSubjectDn(registered, { thumbprint: 'thumb', verified: true, subjectDn: 'CN=rp' })).toBe(true)
    expect(matchesSubjectDn(registered, { thumbprint: 'thumb', verified: false, subjectDn: 'CN=rp' })).toBe(false)
  })

  test('self_signed_tls_client_auth matches the registered certificate whether or not a CA verified it', () => {
    expect(matchesRegisteredCertificate(registered, { thumbprint: 'thumb', verified: false })).toBe(true)
    expect(matchesRegisteredCertificate(registered, { thumbprint: 'other', verified: false })).toBe(false)
  })
})
