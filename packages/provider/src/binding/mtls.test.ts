import { describe, expect, test } from 'bun:test'
import type { Client } from '@oidcraft/adapter'
import { withHashedArtifacts } from '../artifacts'
import { adapter, basic, build, client, ISSUER, REDIRECT, tokensFor, useFlow } from '../test-flow'
import { certificateThumbprint, matchesRegisteredCertificate, matchesTlsClientAuth, parseDistinguishedName } from './mtls'

const stub = (over: Partial<Client> = {}) => ({ clientId: 'rp', ...over }) as Client

describe('distinguished names compare as names, not strings (RFC 8705 §2.1.2, RFC 4517 §4.2.15)', () => {
  const same = (a: string, b: string) =>
    matchesTlsClientAuth(stub({ tlsClientAuthSubjectDn: a }), { thumbprint: 't', verified: true, subjectDn: b })

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
  const registered = stub({ tlsClientAuthSubjectDn: 'CN=rp', jwks: { keys: [{ 'x5t#S256': 'thumb' }] } })

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
  const matches = (over: Partial<Client>) => matchesTlsClientAuth(stub(over), certificate)

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
    expect(matchesTlsClientAuth(stub({ tlsClientAuthSanDns: 'rp.example.com' }), { ...certificate, verified: false })).toBe(false)
    expect(matches({ tlsClientAuthSanDns: 'rp.example.com', tlsClientAuthSubjectDn: 'CN=rp' })).toBe(false)
    expect(matches({})).toBe(false)
  })
})

useFlow()

const DER = new Uint8Array([0x30, 0x82, 0x01, 0x0a, 0x02, 0x01, 0x05])
const certificate = { thumbprint: await certificateThumbprint(DER), verified: true, subjectDn: 'CN=rp,O=Example' }

describe('FR-C4 and FR-C13: mTLS', () => {
  const mtlsProvider = () =>
    build({ capabilities: { clientCertificate: true }, clientAuthMethods: ['tls_client_auth', 'self_signed_tls_client_auth', 'none'] })

  test('tls_client_auth authenticates by the registered subject DN', async () => {
    await adapter.clients.upsert?.(client({ tokenEndpointAuthMethod: 'tls_client_auth', tlsClientAuthSubjectDn: 'CN=rp,O=Example' }))
    const provider = mtlsProvider()
    const response = await provider.handle(
      new Request(`${ISSUER}/token`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'authorization_code', client_id: 'rp', code: 'x', redirect_uri: REDIRECT }).toString()
      }),
      { clientCertificate: certificate }
    )
    // Past authentication: the failure is now the bogus code, not the client.
    expect((await response.json()).error).toBe('invalid_grant')
  })

  // RFC 8705 §2.1.2: a SAN instead of the subject, whatever the subject says.
  test('tls_client_auth authenticates by a registered SAN', async () => {
    await adapter.clients.upsert?.(client({ tokenEndpointAuthMethod: 'tls_client_auth', tlsClientAuthSanIp: '2001:db8::1' }))
    const provider = mtlsProvider()
    const present = (sanIps: string[]) =>
      provider.handle(
        new Request(`${ISSUER}/token`, {
          method: 'POST',
          headers: { 'content-type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ grant_type: 'authorization_code', client_id: 'rp', code: 'x', redirect_uri: REDIRECT }).toString()
        }),
        { clientCertificate: { ...certificate, subjectDn: 'CN=anyone', sanIps } }
      )
    expect((await (await present(['2001:DB8:0:0:0:0:0:1'])).json()).error).toBe('invalid_grant')
    expect((await (await present(['2001:db8::2'])).json()).error).toBe('invalid_client')
  })

  test('a different subject DN is refused', async () => {
    await adapter.clients.upsert?.(client({ tokenEndpointAuthMethod: 'tls_client_auth', tlsClientAuthSubjectDn: 'CN=someone-else' }))
    const provider = mtlsProvider()
    const response = await provider.handle(
      new Request(`${ISSUER}/token`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'authorization_code', client_id: 'rp', code: 'x' }).toString()
      }),
      { clientCertificate: certificate }
    )
    expect((await response.json()).error).toBe('invalid_client')
  })

  test('no certificate at all is refused', async () => {
    await adapter.clients.upsert?.(client({ tokenEndpointAuthMethod: 'tls_client_auth', tlsClientAuthSubjectDn: 'CN=rp,O=Example' }))
    const provider = mtlsProvider()
    const response = await provider.handle(
      new Request(`${ISSUER}/token`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'authorization_code', client_id: 'rp', code: 'x' }).toString()
      })
    )
    expect((await response.json()).error_description).toContain('no client certificate was presented')
  })

  test('self_signed_tls_client_auth matches the registered thumbprint', async () => {
    const thumbprint = await certificateThumbprint(DER)
    await adapter.clients.upsert?.(
      client({ tokenEndpointAuthMethod: 'self_signed_tls_client_auth', jwks: { keys: [{ 'x5t#S256': thumbprint }] } })
    )
    const provider = mtlsProvider()
    const response = await provider.handle(
      new Request(`${ISSUER}/token`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'authorization_code', client_id: 'rp', code: 'x' }).toString()
      }),
      { clientCertificate: certificate }
    )
    expect((await response.json()).error).toBe('invalid_grant')
  })

  // FR-R5 / G-8: a runtime that cannot supply a certificate must not advertise these.
  test('the methods are absent from discovery where no certificate can arrive', async () => {
    await adapter.clients.upsert?.(client())
    const metadata = await (await build().handle(new Request(`${ISSUER}/.well-known/openid-configuration`))).json()
    expect(metadata.token_endpoint_auth_methods_supported).not.toContain('tls_client_auth')
    expect(metadata).not.toHaveProperty('tls_client_certificate_bound_access_tokens')

    const capable = await (await mtlsProvider().handle(new Request(`${ISSUER}/.well-known/openid-configuration`))).json()
    expect(capable.tls_client_certificate_bound_access_tokens).toBe(true)
  })

  test('a certificate-bound token is refused without the certificate', async () => {
    await adapter.clients.upsert?.(client({ certificateBoundAccessTokens: true }))
    const provider = build({ capabilities: { clientCertificate: true } })
    const issued = await tokensFor(provider, 'rp', { clientCertificate: certificate })
    const stored = await withHashedArtifacts(adapter).artifacts.find('access_token', issued.access_token)
    expect((stored?.payload.cnf as { 'x5t#S256'?: string } | undefined)?.['x5t#S256']).toBe(await certificateThumbprint(DER))

    const without = await provider.handle(
      new Request(`${ISSUER}/userinfo`, { headers: { authorization: `Bearer ${issued.access_token}` } })
    )
    expect(without.status).toBe(401)

    const with_ = await provider.handle(
      new Request(`${ISSUER}/userinfo`, { headers: { authorization: `Bearer ${issued.access_token}` } }),
      { clientCertificate: certificate }
    )
    expect(with_.status).toBe(200)
  })

  const form = (path: string, body: Record<string, string>, authorization?: string) =>
    new Request(`${ISSUER}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', ...(authorization && { authorization }) },
      body: new URLSearchParams(body).toString()
    })

  // FR-C4: a client whose only credential is its certificate must be able to use every endpoint that authenticates it.
  test('tls_client_auth works at revocation and introspection, not only the token endpoint', async () => {
    await adapter.clients.upsert?.(client({ tokenEndpointAuthMethod: 'tls_client_auth', tlsClientAuthSubjectDn: 'CN=rp,O=Example' }))
    const provider = mtlsProvider()
    const introspected = await provider.handle(form('/introspect', { client_id: 'rp', token: 'nope' }), { clientCertificate: certificate })
    expect(await introspected.json()).toEqual({ active: false })
    const revoked = await provider.handle(form('/revoke', { client_id: 'rp', token: 'nope' }), { clientCertificate: certificate })
    expect(revoked.status).toBe(200)
    expect((await provider.handle(form('/revoke', { client_id: 'rp', token: 'nope' }))).status).toBe(401)
  })

  // RFC 8705 §3: the binding is not a property of the first access token only.
  test('a refreshed access token stays bound to the certificate', async () => {
    await adapter.clients.upsert?.(client({ certificateBoundAccessTokens: true, scopes: ['openid', 'profile', 'offline_access'] }))
    const provider = build({ capabilities: { clientCertificate: true } })
    const issued = await tokensFor(provider, 'rp', { clientCertificate: certificate }, { scope: 'openid offline_access' })
    expect(issued.refresh_token).toBeTruthy()

    const refreshed = await (
      await provider.handle(form('/token', { grant_type: 'refresh_token', refresh_token: issued.refresh_token }, basic()), {
        clientCertificate: certificate
      })
    ).json()
    const stored = await withHashedArtifacts(adapter).artifacts.find('access_token', refreshed.access_token)
    expect((stored?.payload.cnf as { 'x5t#S256'?: string } | undefined)?.['x5t#S256']).toBe(certificate.thumbprint)
  })

  // RFC 8705 §4: a public client has no other credential, so its refresh token is held to the certificate.
  test("a public client's refresh token needs the same certificate", async () => {
    await adapter.clients.upsert?.(
      client({ tokenEndpointAuthMethod: 'none', certificateBoundAccessTokens: true, scopes: ['openid', 'profile', 'offline_access'] })
    )
    const provider = mtlsProvider()
    const issued = await tokensFor(provider, 'rp', { clientCertificate: certificate }, { scope: 'openid offline_access' })
    const refresh = (clientCertificate: typeof certificate) =>
      provider.handle(form('/token', { grant_type: 'refresh_token', client_id: 'rp', refresh_token: issued.refresh_token }), {
        clientCertificate
      })

    const other = await refresh({ ...certificate, thumbprint: 'someone-elses' })
    expect((await other.json()).error_description).toContain('different certificate')
    expect((await refresh(certificate)).status).toBe(200)
  })
})
