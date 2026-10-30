/// <reference types="bun" />
import { base64url, decodeJwt, exportJWK, generateKeyPair, SignJWT } from 'jose'
import type { Adapter, Provider } from 'oidcraft'

/**
 * A FAPI 2.0 client beside the demo's public ones (FR-C21): it pushes its request with a client
 * assertion and a DPoP proof, and redeems the code with DPoP. A FAPI client is confidential, so it
 * lives here on the server rather than in a browser app. Its keys are this process's own.
 */
export const FAPI_DEMO_CLIENT_ID = 'fapi-demo'

const ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'

const clientKey = await generateKeyPair('ES256', { extractable: true })
const dpopKey = await generateKeyPair('ES256', { extractable: true })

const random = () => base64url.encode(crypto.getRandomValues(new Uint8Array(32)))
const sha256 = async (value: string) =>
  base64url.encode(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))))

/** FAPI 2.0 refuses an http redirect for a web client, so without an https issuer there is no demo to seed. */
export const seedFapiDemoClient = async (adapter: Adapter, issuer: string) => {
  if (!issuer.startsWith('https:')) {
    console.log('[oidcraft] no FAPI demo: it needs an https issuer, see SERVER_TLS_CERT in .env.example')
    return
  }
  await adapter.clients.upsert?.({
    clientId: FAPI_DEMO_CLIENT_ID,
    clientName: 'FAPI 2.0 demo client',
    profile: 'fapi2',
    redirectUris: [`${issuer}/fapi-demo/callback`],
    grantTypes: ['authorization_code', 'refresh_token'],
    responseTypes: ['code'],
    scopes: ['openid', 'profile', 'offline_access'],
    tokenEndpointAuthMethod: 'private_key_jwt',
    jwks: { keys: [{ ...(await exportJWK(clientKey.publicKey)), alg: 'ES256', use: 'sig' }] },
    createdAt: new Date(),
    updatedAt: new Date()
  })
  console.log(`[oidcraft] registered FAPI 2.0 demo client ${FAPI_DEMO_CLIENT_ID} -> ${issuer}/fapi-demo`)
}

const assertion = (issuer: string) =>
  new SignJWT({ jti: random() })
    .setProtectedHeader({ alg: 'ES256' })
    .setIssuer(FAPI_DEMO_CLIENT_ID)
    .setSubject(FAPI_DEMO_CLIENT_ID)
    .setAudience(issuer)
    .setIssuedAt()
    .setExpirationTime('1m')
    .sign(clientKey.privateKey)

const proof = async (method: string, uri: string, accessToken?: string) =>
  new SignJWT({ jti: random(), htm: method, htu: uri, ...(accessToken && { ath: await sha256(accessToken) }) })
    .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: await exportJWK(dpopKey.publicKey) })
    .setIssuedAt()
    .sign(dpopKey.privateKey)

const post = async (provider: Provider, path: string, body: Record<string, string>) => {
  const uri = `${provider.config.issuer}${path}`
  const form = { ...body, client_assertion_type: ASSERTION_TYPE, client_assertion: await assertion(provider.config.issuer) }
  return provider.handle(
    new Request(uri, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', dpop: await proof('POST', uri) },
      body: new URLSearchParams(form).toString()
    })
  )
}

// state → code_verifier, for the one round trip through the browser.
const pending = new Map<string, string>()

/** `/fapi-demo` starts the flow; `/fapi-demo/callback` redeems the code and shows what came back. */
export const fapiDemoRoutes = async (provider: Provider, url: URL) => {
  const { issuer } = provider.config
  if (url.pathname === '/fapi-demo') {
    const verifier = random()
    const state = random()
    pending.set(state, verifier)
    const pushed = await post(provider, '/request', {
      response_type: 'code',
      client_id: FAPI_DEMO_CLIENT_ID,
      redirect_uri: `${issuer}/fapi-demo/callback`,
      scope: 'openid profile offline_access',
      state,
      code_challenge: await sha256(verifier),
      code_challenge_method: 'S256'
    })
    if (!pushed.ok) return pushed
    const { request_uri } = (await pushed.json()) as { request_uri: string }
    return Response.redirect(`${issuer}/authorize?${new URLSearchParams({ client_id: FAPI_DEMO_CLIENT_ID, request_uri })}`, 303)
  }

  if (url.pathname === '/fapi-demo/callback') {
    const state = url.searchParams.get('state') ?? ''
    const verifier = pending.get(state)
    pending.delete(state)
    if (url.searchParams.has('error') || !verifier) {
      return Response.json({ error: url.searchParams.get('error') ?? 'unknown state' }, { status: 400 })
    }
    const token = await post(provider, '/token', {
      grant_type: 'authorization_code',
      code: url.searchParams.get('code') ?? '',
      redirect_uri: `${issuer}/fapi-demo/callback`,
      code_verifier: verifier
    })
    const body = (await token.json()) as Record<string, string>
    if (!token.ok) return Response.json(body, { status: token.status })
    const userinfo = await provider.handle(
      new Request(`${issuer}/userinfo`, {
        headers: { authorization: `DPoP ${body.access_token}`, dpop: await proof('GET', `${issuer}/userinfo`, body.access_token) }
      })
    )
    return Response.json({
      token_type: body.token_type,
      scope: body.scope,
      refresh_token: body.refresh_token ? 'issued; under FAPI 2.0 it does not rotate' : 'not issued',
      id_token: body.id_token && decodeJwt(body.id_token),
      userinfo: await userinfo.json()
    })
  }
  return undefined
}
