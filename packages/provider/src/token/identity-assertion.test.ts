import { beforeEach, describe, expect, test } from 'bun:test'
import { exportJWK, generateKeyPair, type JWK, SignJWT, UnsecuredJWT } from 'jose'
import type { AssertionTrust, Client, TrustedIssuer } from '../index'
import type { Provider } from '../provider'
import { adapter, basic, build, client, ISSUER, useFlow } from '../test-flow'

const JWT_BEARER_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:jwt-bearer'
const ID_JAG_PROFILE = 'urn:ietf:params:oauth:grant-profile:id-jag'
const ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'

const IDP = 'https://idp.example.com'
const OTHER_IDP = 'https://other-idp.example.com'
const MULTI = 'https://login.multi.example.com'
const MCP = 'https://mcp.example.com/mcp'
const API = 'https://api.example.com'

const ES256 = await generateKeyPair('ES256', { extractable: true })
const RS256 = await generateKeyPair('RS256', { extractable: true })
const OTHER = await generateKeyPair('ES256', { extractable: true })
const ATTACKER = await generateKeyPair('ES256', { extractable: true })
const MULTI_KEY = await generateKeyPair('ES256', { extractable: true })
const publicJwk = async (key: CryptoKey) => ({ ...(await exportJWK(key)), kid: crypto.randomUUID() }) as JWK

const IDP_KEYS = { keys: [await publicJwk(ES256.publicKey), await publicJwk(RS256.publicKey)] }

let trusted: Record<string, TrustedIssuer>
let asked: Parameters<AssertionTrust>[0][]
let provider: Provider

const trust: AssertionTrust = input => {
  asked.push(input)
  return trusted[input.tenant ? `${input.iss}#${input.tenant}` : input.iss]
}

const now = () => Math.floor(Date.now() / 1000)

type Options = { key?: CryptoKey | Uint8Array; alg?: string; header?: Record<string, unknown> }

/** An ID-JAG for `rp`, from IDP, about `idp-ada`; a claim set to undefined is left out. */
const idJag = (claims: Record<string, unknown> = {}, { key = ES256.privateKey, alg = 'ES256', header = {} }: Options = {}) => {
  const payload: Record<string, unknown> = {
    iss: IDP,
    sub: 'idp-ada',
    aud: ISSUER,
    client_id: 'rp',
    jti: crypto.randomUUID(),
    iat: now(),
    exp: now() + 60,
    scope: 'openid tools',
    ...claims
  }
  for (const [name, value] of Object.entries(payload)) if (value === undefined) delete payload[name]
  return new SignJWT(payload).setProtectedHeader({ alg, typ: 'oauth-id-jag+jwt', ...header }).sign(key)
}

const post = (path: string, body: Record<string, string>, as: string | undefined = 'rp') =>
  provider.handle(
    new Request(`${ISSUER}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', ...(as && { authorization: basic(as) }) },
      body: new URLSearchParams(body).toString()
    })
  )

const redeem = async (assertion: string | Promise<string>, extra: Record<string, string> = {}, as?: string) =>
  post('/token', { grant_type: JWT_BEARER_GRANT_TYPE, assertion: await assertion, ...extra }, as)

const errorOf = async (response: Response) => ((await response.json()) as { error?: string }).error

const introspect = async (token: string, as = 'rp') => (await post('/introspect', { token }, as)).json()

const link = (subject: string, accountId: string, upstream = 'idp') =>
  adapter.identities?.upsert({ accountId, upstream, subject, claims: {}, createdAt: new Date() })

const withBearer = (over: Partial<Client> = {}) =>
  client({
    grantTypes: ['authorization_code', 'refresh_token', JWT_BEARER_GRANT_TYPE],
    scopes: ['openid', 'profile', 'offline_access', 'tools'],
    ...over
  })

const configure = ({ trusting = true, ...over }: Parameters<typeof build>[0] & { trusting?: boolean } = {}) => {
  provider = build({
    scopes: ['openid', 'profile', 'email', 'offline_access', 'tools'],
    resources: [
      { uri: MCP, resourceServer: 'mcp-server' },
      { uri: API, resourceServer: 'api-server' }
    ],
    ...(trusting && { assertionTrust: trust }),
    ...over
  })
}

useFlow()

beforeEach(async () => {
  trusted = {
    [IDP]: { issuer: IDP, jwks: IDP_KEYS, upstream: 'idp' },
    [OTHER_IDP]: { issuer: OTHER_IDP, jwks: { keys: [await publicJwk(OTHER.publicKey)] }, upstream: 'other-idp' }
  }
  asked = []
  await adapter.clients.upsert?.(withBearer())
  await adapter.clients.upsert?.(withBearer({ clientId: 'other' }))
  await adapter.clients.upsert?.(client({ clientId: 'mcp-server', resourceServer: true, redirectUris: [], grantTypes: [] }))
  await adapter.clients.upsert?.(client({ clientId: 'api-server', resourceServer: true, redirectUris: [], grantTypes: [] }))
  await link('idp-ada', 'ada')
  configure()
})

describe('identity assertion grants (FR-C24)', () => {
  test('a trusted, linked assertion is an access token for the linked account', async () => {
    const response = await redeem(idJag())
    expect(response.status).toBe(200)
    const body = await response.json()
    expect(body).toMatchObject({ token_type: 'Bearer', scope: 'openid tools' })
    expect(body.expires_in).toBeGreaterThan(0)
    expect(await introspect(body.access_token)).toMatchObject({ active: true, sub: 'ada', client_id: 'rp', scope: 'openid tools' })
  })

  // §4.4.4: the IdP decides each time, so nothing here outlives its say-so.
  test('issues neither a refresh token nor an ID token', async () => {
    const body = await (await redeem(idJag({ scope: 'openid offline_access tools' }))).json()
    expect(body.refresh_token).toBeUndefined()
    expect(body.id_token).toBeUndefined()
    expect(body.scope).toBe('openid tools')
  })

  test('records no consent a later browser sign-in could skip its screen on', async () => {
    expect((await redeem(idJag())).status).toBe(200)
    expect(await adapter.grants.findByAccountAndClient('ada', 'rp')).toBeUndefined()
  })

  test('the trust is asked with the unverified iss, tenant and aud_tenant, and the client', async () => {
    await redeem(idJag({ aud_tenant: 'workspace-1' }))
    expect(asked).toHaveLength(1)
    expect(asked[0]).toMatchObject({ iss: IDP, tenant: undefined, aud_tenant: 'workspace-1' })
    expect(asked[0]?.client.clientId).toBe('rp')
  })

  test('an RS256 assertion is accepted too', async () => {
    expect((await redeem(idJag({}, { key: RS256.privateKey, alg: 'RS256' }))).status).toBe(200)
  })

  test('an aud of a one-element array is accepted', async () => {
    expect((await redeem(idJag({ aud: [ISSUER] }))).status).toBe(200)
  })

  test('within 60 s of skew, a just-expired or just-future assertion is accepted', async () => {
    expect((await redeem(idJag({ exp: now() - 30 }))).status).toBe(200)
    expect((await redeem(idJag({ iat: now() + 30, exp: now() + 90 }))).status).toBe(200)
  })
})

describe('discovery and configuration (FR-C24)', () => {
  const metadata = async () => (await provider.handle(new Request(`${ISSUER}/.well-known/oauth-authorization-server`))).json()

  test('advertises the bearer grant and the ID-JAG profile only when there is a trust', async () => {
    const on = await metadata()
    expect(on.grant_types_supported).toContain(JWT_BEARER_GRANT_TYPE)
    expect(on.authorization_grant_profiles_supported).toEqual([ID_JAG_PROFILE])

    configure({ trusting: false })
    const off = await metadata()
    expect(off.grant_types_supported).not.toContain(JWT_BEARER_GRANT_TYPE)
    expect(off.authorization_grant_profiles_supported).toBeUndefined()
  })

  test('without a trust the grant type is not supported, whatever the client registered', async () => {
    configure({ trusting: false })
    expect(await errorOf(await redeem(idJag()))).toBe('unsupported_grant_type')
  })

  test('a trust without the identities store is refused at construction', () => {
    const { identities: _omitted, ...withoutIdentities } = adapter
    expect(() => configure({ adapter: withoutIdentities })).toThrow('identities')
  })

  test('a client not registered for the bearer grant type may not use it', async () => {
    await adapter.clients.upsert?.(client())
    expect(await errorOf(await redeem(idJag()))).toBe('unauthorized_client')
  })
})

describe('the assertion is checked, each failure invalid_grant (FR-C24)', () => {
  const refused = async (assertion: Promise<string> | string) => {
    const response = await redeem(assertion)
    expect(response.status).toBe(400)
    expect(await errorOf(response)).toBe('invalid_grant')
  }

  test('an issuer the trust does not know', () => refused(idJag({ iss: 'https://unknown.example.com' })))

  test('a trust naming any issuer but iss, exactly', async () => {
    trusted[IDP] = { issuer: `${IDP}/`, jwks: IDP_KEYS, upstream: 'idp' }
    await refused(idJag())
  })

  test("a signature by a key outside the issuer's set", () => refused(idJag({}, { key: OTHER.privateKey })))

  test('a key the header carries, never trusted', async () =>
    refused(idJag({}, { key: ATTACKER.privateKey, header: { jwk: await exportJWK(ATTACKER.publicKey) } })))

  test('an unsigned assertion', () =>
    refused(new UnsecuredJWT({ iss: IDP, sub: 'idp-ada', aud: ISSUER, client_id: 'rp', jti: 'j', iat: now(), exp: now() + 60 }).encode()))

  test('an HMAC, even when the trust lists it', async () => {
    const secret = crypto.getRandomValues(new Uint8Array(32))
    trusted[IDP] = {
      issuer: IDP,
      jwks: { keys: [{ kty: 'oct', k: Buffer.from(secret).toString('base64url') }] },
      upstream: 'idp',
      algorithms: ['HS256']
    }
    await refused(idJag({}, { key: secret, alg: 'HS256' }))
  })

  test('a trusted key set that is not a JWK Set', async () => {
    trusted[IDP] = { issuer: IDP, jwks: { keys: 'not keys' } as unknown as TrustedIssuer['jwks'], upstream: 'idp' }
    await refused(idJag())
  })

  test('an algorithm the trust does not allow', async () => {
    trusted[IDP] = { issuer: IDP, jwks: IDP_KEYS, upstream: 'idp', algorithms: ['ES256'] }
    await refused(idJag({}, { key: RS256.privateKey, alg: 'RS256' }))
  })

  test('a typ other than oauth-id-jag+jwt', () => refused(idJag({}, { header: { typ: 'JWT' } })))

  test('an aud other than this issuer', () => refused(idJag({ aud: 'https://elsewhere.example.com' })))

  test('an aud naming this issuer among others', () => refused(idJag({ aud: [ISSUER, 'https://elsewhere.example.com'] })))

  test('a client_id other than the authenticated client', () => refused(idJag({ client_id: 'other' })))

  test.each(['sub', 'jti', 'iat', 'exp'])('a missing %s', claim => refused(idJag({ [claim]: undefined })))

  test.each(['sub', 'jti'])('a %s that is not a string', claim => refused(idJag({ [claim]: 42 })))

  test('an exp more than 60 s past', () => refused(idJag({ exp: now() - 90 })))

  test('an iat more than 60 s ahead', () => refused(idJag({ iat: now() + 90, exp: now() + 120 })))

  test('an nbf more than 60 s ahead', () => refused(idJag({ nbf: now() + 90 })))

  test('a lifetime over 300 s', () => refused(idJag({ exp: now() + 600 })))

  // §9.11: an assertion bound to a key this provider cannot check is refused, never redeemed as a bearer one.
  test('a cnf', () => refused(idJag({ cnf: { jkt: 'thumbprint' } })))

  // FR-M3: a replay means the assertion leaked, so the host hears of it.
  test('a replayed jti, reported to onAudit', async () => {
    const events: { action: string; clientId?: string; detail?: Record<string, unknown> }[] = []
    configure({ onAudit: event => void events.push(event) })
    const assertion = await idJag()
    expect((await redeem(assertion)).status).toBe(200)
    await refused(assertion)
    expect(events).toContainEqual(
      expect.objectContaining({ action: 'token.replay', clientId: 'rp', detail: { kind: 'identity_assertion', issuer: IDP } })
    )
  })

  test('a jti is single-use per issuer, not across them', async () => {
    await link('other-ada', 'ada', 'other-idp')
    const jti = crypto.randomUUID()
    expect((await redeem(idJag({ jti }))).status).toBe(200)
    expect((await redeem(idJag({ jti, iss: OTHER_IDP, sub: 'other-ada' }, { key: OTHER.privateKey }))).status).toBe(200)
  })
})

describe('a multi-tenant issuer (FR-C24, §6.1)', () => {
  beforeEach(async () => {
    trusted[`${MULTI}#acme`] = {
      issuer: MULTI,
      jwks: { keys: [await publicJwk(MULTI_KEY.publicKey)] },
      upstream: 'multi-acme',
      tenant: 'acme'
    }
    trusted[MULTI] = trusted[`${MULTI}#acme`] as TrustedIssuer
    await link('acme-ada', 'ada', 'multi-acme')
  })

  const fromMulti = (claims: Record<string, unknown>) => idJag({ iss: MULTI, sub: 'acme-ada', ...claims }, { key: MULTI_KEY.privateKey })

  test("the trusted tenant's assertion is accepted", async () => {
    expect((await redeem(fromMulti({ tenant: 'acme' }))).status).toBe(200)
  })

  test('one without a tenant is refused', async () => {
    expect(await errorOf(await redeem(fromMulti({})))).toBe('invalid_grant')
  })

  test("one naming another tenant than the trust's is refused", async () => {
    trusted[`${MULTI}#evil`] = trusted[MULTI] as TrustedIssuer
    expect(await errorOf(await redeem(fromMulti({ tenant: 'evil' })))).toBe('invalid_grant')
  })
})

describe('the client authenticates (FR-C24, §4.4)', () => {
  test('a public client is invalid_client, whatever the assertion', async () => {
    const { clientSecretHash: _omitted, ...open } = withBearer({ clientId: 'public', tokenEndpointAuthMethod: 'none' })
    await adapter.clients.upsert?.(open)
    const response = await redeem(idJag({ client_id: 'public' }), { client_id: 'public' }, '')
    expect(await errorOf(response)).toBe('invalid_client')
  })

  test("Claude's private_key_jwt metadata-document client redeems one", async () => {
    const CLAUDE = 'https://claude.ai/oauth/mcp-oauth-client-metadata/confidential_client'
    const clientKey = await generateKeyPair('ES256', { extractable: true })
    const document = {
      client_id: CLAUDE,
      client_name: 'Claude',
      redirect_uris: ['https://claude.ai/api/mcp/auth_callback'],
      grant_types: ['authorization_code', 'refresh_token', JWT_BEARER_GRANT_TYPE],
      token_endpoint_auth_method: 'private_key_jwt',
      jwks: { keys: [await exportJWK(clientKey.publicKey)] }
    }
    const clientAssertion = () =>
      new SignJWT({ jti: crypto.randomUUID() })
        .setProtectedHeader({ alg: 'ES256' })
        .setIssuer(CLAUDE)
        .setSubject(CLAUDE)
        .setAudience(ISSUER)
        .setIssuedAt()
        .setExpirationTime('1m')
        .sign(clientKey.privateKey)
    const asClaude = async () =>
      redeem(
        idJag({ client_id: CLAUDE, resource: MCP }),
        { resource: MCP, client_assertion_type: ASSERTION_TYPE, client_assertion: await clientAssertion() },
        ''
      )

    configure({ resolveClientMetadata: async id => (id === CLAUDE ? document : undefined) })
    const response = await asClaude()
    expect(response.status).toBe(200)
    expect(await introspect((await response.json()).access_token, 'mcp-server')).toMatchObject({ active: true, sub: 'ada', aud: MCP })

    // Off, the same document still resolves, and the grant type is simply not supported (FR-C20, FR-C6).
    configure({ trusting: false, resolveClientMetadata: async id => (id === CLAUDE ? document : undefined) })
    expect(await errorOf(await asClaude())).toBe('unsupported_grant_type')
  })
})

describe('the account is (upstream, sub) and nothing else (FR-C24, FR-F5)', () => {
  test('an unlinked subject is access_denied', async () => {
    expect(await errorOf(await redeem(idJag({ sub: 'idp-stranger' })))).toBe('access_denied')
  })

  // §9.8, NFR-S8: only the issuing tenant's administrators vouch for either.
  test('neither email nor aud_sub finds an account', async () => {
    const response = await redeem(idJag({ sub: 'idp-stranger', email: 'ada@example.com', email_verified: true, aud_sub: 'ada' }))
    expect(await errorOf(response)).toBe('access_denied')
  })

  test("a subject linked under another issuer's upstream is not this one's", async () => {
    await link('other-only', 'ada', 'other-idp')
    expect(await errorOf(await redeem(idJag({ sub: 'other-only' })))).toBe('access_denied')
  })

  test('a link to an account that no longer exists is access_denied', async () => {
    await link('idp-ghost', 'ghost')
    expect(await errorOf(await redeem(idJag({ sub: 'idp-ghost' })))).toBe('access_denied')
  })
})

describe('scopes (FR-C24)', () => {
  const scopeOf = async (response: Response) => {
    expect(response.status).toBe(200)
    return ((await response.json()) as { scope: string }).scope
  }

  test("the request's scope, narrowed from the assertion's", async () => {
    expect(await scopeOf(await redeem(idJag(), { scope: 'tools' }))).toBe('tools')
  })

  test("the assertion's, without a request scope, less what the client may not have", async () => {
    expect(await scopeOf(await redeem(idJag({ scope: 'tools email' })))).toBe('tools')
  })

  test("the client's defaults, less offline_access, when neither names any", async () => {
    expect(await scopeOf(await redeem(idJag({ scope: undefined })))).toBe('openid profile tools')
  })

  test("a requested scope beyond the assertion's is invalid_scope", async () => {
    expect(await errorOf(await redeem(idJag(), { scope: 'profile' }))).toBe('invalid_scope')
  })

  test("a requested scope beyond the client's is invalid_scope", async () => {
    expect(await errorOf(await redeem(idJag({ scope: 'tools email' }), { scope: 'email' }))).toBe('invalid_scope')
  })

  test('offline_access, requested, is invalid_scope', async () => {
    expect(await errorOf(await redeem(idJag({ scope: 'tools offline_access' }), { scope: 'offline_access' }))).toBe('invalid_scope')
  })
})

describe('resources (FR-C24, FR-C19)', () => {
  const audienceOf = async (response: Response, as: string) => {
    expect(response.status).toBe(200)
    return (await introspect(((await response.json()) as { access_token: string }).access_token, as)).aud
  }

  test("the request's resource, among the assertion's", async () => {
    expect(await audienceOf(await redeem(idJag({ resource: [MCP, API] }), { resource: API }), 'api-server')).toBe(API)
  })

  test("the assertion's one resource, when the request names none", async () => {
    expect(await audienceOf(await redeem(idJag({ resource: MCP })), 'mcp-server')).toBe(MCP)
  })

  test('a requested resource the assertion does not name is invalid_target', async () => {
    expect(await errorOf(await redeem(idJag({ resource: MCP }), { resource: API }))).toBe('invalid_target')
  })

  test('several in the assertion and none requested is invalid_target: a token has one audience', async () => {
    expect(await errorOf(await redeem(idJag({ resource: [MCP, API] })))).toBe('invalid_target')
  })

  test('an assertion naming a resource that is not configured is invalid_grant', async () => {
    expect(await errorOf(await redeem(idJag({ resource: 'https://elsewhere.example.com' })))).toBe('invalid_grant')
  })

  test('a resource kept to other clients is invalid_target', async () => {
    configure({ resources: [{ uri: MCP, resourceServer: 'mcp-server', clients: ['other'] }] })
    expect(await errorOf(await redeem(idJag({ resource: MCP })))).toBe('invalid_target')
  })
})

describe('a malformed scope claim (FR-C24)', () => {
  // Read as absent, it would lift the IdP's limit to everything the client is registered for.
  test('a scope that is not a string is invalid_grant, with or without a requested scope', async () => {
    expect(await errorOf(await redeem(idJag({ scope: ['tools'] })))).toBe('invalid_grant')
    expect(await errorOf(await redeem(idJag({ scope: ['tools'] }), { scope: 'profile' }))).toBe('invalid_grant')
  })
})

describe('a refused request does not spend its assertion (FR-C24, NFR-S5)', () => {
  let events: { action: string }[]

  beforeEach(() => {
    events = []
    configure({ onAudit: event => void events.push(event) })
  })

  test('after invalid_scope, the same assertion with a corrected scope', async () => {
    const assertion = await idJag()
    expect(await errorOf(await redeem(assertion, { scope: 'profile' }))).toBe('invalid_scope')
    expect((await redeem(assertion, { scope: 'tools' })).status).toBe(200)
    expect(events.map(event => event.action)).not.toContain('token.replay')
  })

  test('after access_denied, the same assertion once the subject is linked', async () => {
    const assertion = await idJag({ sub: 'idp-newcomer' })
    expect(await errorOf(await redeem(assertion))).toBe('access_denied')
    await link('idp-newcomer', 'ada')
    expect((await redeem(assertion)).status).toBe(200)
  })

  test("after invalid_target for the assertion's own resource, the same assertion once the client may have it", async () => {
    configure({ resources: [{ uri: MCP, resourceServer: 'mcp-server', clients: ['other'] }] })
    const assertion = await idJag({ resource: MCP })
    expect(await errorOf(await redeem(assertion))).toBe('invalid_target')
    configure({ resources: [{ uri: MCP, resourceServer: 'mcp-server' }] })
    expect((await redeem(assertion)).status).toBe(200)
  })
})

describe('registration (FR-C24, FR-C9)', () => {
  const register = (metadata: Record<string, unknown>) =>
    provider.handle(
      new Request(`${ISSUER}/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ redirect_uris: ['https://app.example.com/cb'], ...metadata })
      })
    )

  test('a public client may not register for the bearer grant type it could never redeem', async () => {
    configure({ features: { dynamicRegistration: true } })
    const refused = await register({ grant_types: ['authorization_code', JWT_BEARER_GRANT_TYPE], token_endpoint_auth_method: 'none' })
    expect(await errorOf(refused)).toBe('invalid_client_metadata')
    const confidential = await register({ grant_types: ['authorization_code', JWT_BEARER_GRANT_TYPE] })
    expect(confidential.status).toBe(201)
  })
})
