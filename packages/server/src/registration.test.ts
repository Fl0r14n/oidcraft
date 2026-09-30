import { beforeEach, describe, expect, test } from 'bun:test'
import { memoryAdapter } from './adapters/memory'
import { OAuthError } from './errors'
import type { Adapter, AuditEvent } from './index'
import { createProvider, type Provider } from './provider'

const ISSUER = 'https://op.example.com'
const REDIRECT = 'https://rp.example.com/cb'

let adapter: Adapter
let provider: Provider
let audit: AuditEvent[]

beforeEach(async () => {
  adapter = await memoryAdapter()
  audit = []
  provider = createProvider({
    issuer: ISSUER,
    adapter,
    features: { dynamicRegistration: true },
    onAudit: event => {
      audit.push(event)
    }
  })
})

const register = (body: Record<string, unknown>, headers: Record<string, string> = {}) =>
  provider.handle(
    new Request(`${ISSUER}/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...headers },
      body: JSON.stringify(body)
    })
  )

const valid = { redirect_uris: [REDIRECT], client_name: 'Demo', scope: 'openid profile' }

describe('dynamic client registration', () => {
  test('registers a client and returns its credentials', async () => {
    const response = await register(valid)
    expect(response.status).toBe(201)
    const body = await response.json()
    expect(body.client_id).toBeTruthy()
    expect(body.client_secret).toBeTruthy()
    expect(body.registration_access_token).toBeTruthy()
    expect(body.registration_client_uri).toContain(body.client_id)
    expect(response.headers.get('cache-control')).toBe('no-store')
  })

  test('the registered client can actually be used', async () => {
    const { client_id } = await (await register(valid)).json()
    expect((await adapter.clients.find(client_id))?.redirectUris).toEqual([REDIRECT])
  })

  // OIDC DCR 1.0 §2: RS256 when omitted, whatever the provider signs with by default (FR-T1).
  test('a dynamic client gets RS256 ID tokens unless it asks otherwise', async () => {
    const { client_id, id_token_signed_response_alg } = await (await register(valid)).json()
    expect(id_token_signed_response_alg).toBe('RS256')
    expect((await adapter.clients.find(client_id))?.idTokenSignedResponseAlg).toBe('RS256')
    expect((await (await register({ ...valid, id_token_signed_response_alg: 'ES256' })).json()).id_token_signed_response_alg).toBe('ES256')
  })

  test('an ID token algorithm the provider holds no key for is refused, none included', async () => {
    expect((await register({ ...valid, id_token_signed_response_alg: 'none' })).status).toBe(400)
    expect((await register({ ...valid, id_token_signed_response_alg: 'PS512' })).status).toBe(400)
  })

  // FR-C3: a client registering itself cannot vouch for itself.
  test('PKCE is forced on regardless of what was asked for', async () => {
    const { client_id } = await (await register({ ...valid, require_pkce: false })).json()
    expect((await adapter.clients.find(client_id))?.requirePkce).toBe(true)
  })

  test('a public client gets no secret', async () => {
    const body = await (await register({ ...valid, token_endpoint_auth_method: 'none' })).json()
    expect(body.client_secret).toBeUndefined()
  })

  // This endpoint lets a stranger write to the client store, so the metadata is checked hard.
  test('redirect_uris is required', async () => {
    expect((await register({ client_name: 'x' })).status).toBe(400)
  })

  test('a non-loopback http redirect_uri is refused', async () => {
    const response = await register({ redirect_uris: ['http://rp.example.com/cb'] })
    expect((await response.json()).error_description).toContain('must be https')
  })

  test('a loopback http redirect_uri is allowed', async () => {
    expect((await register({ redirect_uris: ['http://127.0.0.1:8080/cb'] })).status).toBe(201)
  })

  test('a redirect_uri with a fragment is refused', async () => {
    const response = await register({ redirect_uris: ['https://rp.example.com/cb#x'] })
    expect((await response.json()).error_description).toContain('fragment')
  })

  test('a response_type that issues a token is refused', async () => {
    const response = await register({ ...valid, response_types: ['code token'] })
    expect((await response.json()).error_description).toContain('no tokens from the authorization endpoint')
  })

  test('an unknown scope is refused', async () => {
    const response = await register({ ...valid, scope: 'openid wat' })
    expect((await response.json()).error_description).toContain('unknown scope')
  })

  // tls_client_auth is absent from the defaults because this runtime cannot supply a client
  // certificate at all (FR-R5, G-8), so a client asking to register for it is refused.
  test('an auth method the provider does not offer is refused', async () => {
    const response = await register({ ...valid, token_endpoint_auth_method: 'tls_client_auth' })
    expect((await response.json()).error_description).toContain('not offered')
  })

  test('an auth method the provider does offer is accepted', async () => {
    expect((await register({ ...valid, token_endpoint_auth_method: 'client_secret_jwt' })).status).toBe(201)
  })

  // FR-C9: disabled is the default, and the route does not exist at all.
  test('the endpoint is absent unless the feature is on', async () => {
    const off = createProvider({ issuer: ISSUER, adapter })
    const response = await off.handle(new Request(`${ISSUER}/register`, { method: 'POST', body: '{}' }))
    expect(response.status).toBe(404)
  })

  // OIDC DCR 1.0 §5, FR-C18.
  describe('sector_identifier_uri', () => {
    const SECTOR = 'https://rp.example.com/sector.json'
    const OTHER = 'https://other.example.net/cb'
    const withSectors = (listed: Record<string, unknown>) =>
      createProvider({
        issuer: ISSUER,
        adapter,
        pairwiseSalt: 'a-salt-long-enough-for-pairwise-subjects',
        features: { dynamicRegistration: true },
        resolveSectorIdentifier: async uri => {
          if (!(uri in listed)) throw new Error('unreachable')
          return listed[uri]
        }
      })
    const registerWith = (op: Provider, body: Record<string, unknown>) =>
      op.handle(new Request(`${ISSUER}/register`, { method: 'POST', body: JSON.stringify(body) }))

    test('registers when the sector lists every redirect_uri', async () => {
      const op = withSectors({ [SECTOR]: [REDIRECT, OTHER] })
      const response = await registerWith(op, { ...valid, subject_type: 'pairwise', sector_identifier_uri: SECTOR })
      expect(response.status).toBe(201)
      const { client_id, sector_identifier_uri } = await response.json()
      expect(sector_identifier_uri).toBe(SECTOR)
      expect((await adapter.clients.find(client_id))?.subjectType).toBe('pairwise')
    })

    test('refuses a redirect_uri the sector does not list', async () => {
      const op = withSectors({ [SECTOR]: [OTHER] })
      expect((await registerWith(op, { ...valid, sector_identifier_uri: SECTOR })).status).toBe(400)
    })

    test('refuses a sector that is unreachable, not an array, or not https', async () => {
      const op = withSectors({ [SECTOR]: { redirect_uris: [REDIRECT] } })
      expect((await registerWith(op, { ...valid, sector_identifier_uri: 'https://rp.example.com/missing.json' })).status).toBe(400)
      expect((await registerWith(op, { ...valid, sector_identifier_uri: SECTOR })).status).toBe(400)
      expect((await registerWith(op, { ...valid, sector_identifier_uri: 'http://rp.example.com/sector.json' })).status).toBe(400)
    })

    test('refuses a sector the provider has no way to fetch', async () => {
      expect((await register({ ...valid, sector_identifier_uri: SECTOR })).status).toBe(400)
    })

    // OIDC Core §8.1: otherwise the subject would depend on which redirect_uri was used.
    test('a pairwise client on several hosts must name a sector', async () => {
      const op = withSectors({})
      expect((await registerWith(op, { ...valid, redirect_uris: [REDIRECT, OTHER], subject_type: 'pairwise' })).status).toBe(400)
    })

    test('pairwise is refused where the provider issues none', async () => {
      expect((await register({ ...valid, subject_type: 'pairwise' })).status).toBe(400)
    })
  })

  describe('onRegister exempting a client from PKCE (FR-C3)', () => {
    const vouching = (decision: { requirePkce: boolean }) =>
      createProvider({ issuer: ISSUER, adapter, features: { dynamicRegistration: true }, onRegister: () => decision })
    const registerWith = (provider: ReturnType<typeof vouching>, body: Record<string, unknown>) =>
      provider.handle(new Request(`${ISSUER}/register`, { method: 'POST', body: JSON.stringify(body) }))

    test('exempts a confidential client the host vouched for', async () => {
      const { client_id } = await (await registerWith(vouching({ requirePkce: false }), valid)).json()
      expect((await adapter.clients.find(client_id))?.requirePkce).toBe(false)
    })

    test('refuses to exempt a public client', async () => {
      const response = await registerWith(vouching({ requirePkce: false }), { ...valid, token_endpoint_auth_method: 'none' })
      expect(response.status).toBe(400)
    })

    test('leaves the body readable for the hook and for registration', async () => {
      let seen: unknown
      const reading = createProvider({
        issuer: ISSUER,
        adapter,
        features: { dynamicRegistration: true },
        onRegister: async request => {
          seen = await request.json()
        }
      })
      expect((await registerWith(reading, valid)).status).toBe(201)
      expect(seen).toEqual(valid)
    })
  })

  test('onRegister can refuse an open registration', async () => {
    const gated = createProvider({
      issuer: ISSUER,
      adapter,
      features: { dynamicRegistration: true },
      onRegister: request => {
        if (request.headers.get('authorization') !== 'Bearer initial') {
          throw new OAuthError('access_denied', { description: 'an initial access token is required' })
        }
      }
    })
    const refused = await gated.handle(new Request(`${ISSUER}/register`, { method: 'POST', body: JSON.stringify(valid) }))
    expect(refused.status).toBe(403)
    const allowed = await gated.handle(
      new Request(`${ISSUER}/register`, { method: 'POST', headers: { authorization: 'Bearer initial' }, body: JSON.stringify(valid) })
    )
    expect(allowed.status).toBe(201)
  })

  test('registration emits an audit event', async () => {
    await register(valid)
    expect(audit.map(event => event.action)).toEqual(['client.register'])
  })
})

describe('registration management (RFC 7592)', () => {
  const registered = async () => (await register(valid)).json()

  const call = (method: string, clientId: string, accessToken?: string, body?: unknown) =>
    provider.handle(
      new Request(`${ISSUER}/register?client_id=${encodeURIComponent(clientId)}`, {
        method,
        headers: { 'content-type': 'application/json', ...(accessToken && { authorization: `Bearer ${accessToken}` }) },
        ...(body ? { body: JSON.stringify(body) } : {})
      })
    )

  test('reads itself back with its token', async () => {
    const client = await registered()
    const response = await call('GET', client.client_id, client.registration_access_token)
    expect(response.status).toBe(200)
    expect((await response.json()).client_id).toBe(client.client_id)
  })

  test('updates itself', async () => {
    const client = await registered()
    const response = await call('PUT', client.client_id, client.registration_access_token, {
      ...valid,
      redirect_uris: ['https://rp.example.com/other']
    })
    expect(response.status).toBe(200)
    expect((await adapter.clients.find(client.client_id))?.redirectUris).toEqual(['https://rp.example.com/other'])
  })

  // Identity and the token guarding it are the server's to set, not the client's to choose.
  test('an update cannot change the client_id or its registration token', async () => {
    const client = await registered()
    await call('PUT', client.client_id, client.registration_access_token, {
      ...valid,
      client_id: 'chosen-by-me',
      registration_access_token: 'chosen-by-me'
    })
    const stored = await adapter.clients.find(client.client_id)
    expect(stored?.clientId).toBe(client.client_id)
    expect(stored?.registrationAccessToken).toBe(client.registration_access_token)
  })

  test('deletes itself', async () => {
    const client = await registered()
    expect((await call('DELETE', client.client_id, client.registration_access_token)).status).toBe(204)
    expect(await adapter.clients.find(client.client_id)).toBeUndefined()
  })

  test('without the token it is refused', async () => {
    const client = await registered()
    expect((await call('GET', client.client_id)).status).toBe(401)
    expect((await call('GET', client.client_id, 'wrong')).status).toBe(401)
  })

  test("another client's token does not work", async () => {
    const mine = await registered()
    const theirs = await registered()
    expect((await call('DELETE', mine.client_id, theirs.registration_access_token)).status).toBe(401)
  })

  // Otherwise the endpoint enumerates which client ids exist.
  test('an unknown client is indistinguishable from a wrong token', async () => {
    const unknown = await call('GET', 'does-not-exist', 'whatever')
    const wrong = await call('GET', (await registered()).client_id, 'whatever')
    expect(unknown.status).toBe(wrong.status)
    expect(await unknown.json()).toEqual(await wrong.json())
  })
})
