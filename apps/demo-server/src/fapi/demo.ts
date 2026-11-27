/// <reference types="bun" />

import type { Adapter, Provider } from '@oidcraft/provider'
import { base64url, decodeJwt, exportJWK, generateKeyPair, SignJWT } from 'jose'

/** A FAPI 2.0 client is confidential, so this one lives on the server, with keys of this process's own (FR-C21). */
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

// D-10: the verifier waits in this browser, for ten minutes, never in a map of this process that anyone's visit grows.
const PENDING = 'fapi-demo'
const PENDING_TTL = 600

const pendingCookie = (value: string, maxAge: number) =>
  `${PENDING}=${value}; Path=/fapi-demo; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`

const pendingOf = (request: Request) => {
  for (const pair of request.headers.get('cookie')?.split(';') ?? []) {
    const [name, value] = pair.trim().split('=')
    if (name === PENDING && value) {
      const [state, verifier] = value.split('.')
      if (state && verifier) return { state, verifier }
    }
  }
  return undefined
}

export const fapiDemoRoutes = async (provider: Provider, request: Request, url: URL) => {
  const { issuer } = provider.config
  if (url.pathname === '/fapi-demo') {
    const verifier = random()
    const state = random()
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
    return new Response(null, {
      status: 303,
      headers: {
        location: `${issuer}/authorize?${new URLSearchParams({ client_id: FAPI_DEMO_CLIENT_ID, request_uri })}`,
        'set-cookie': pendingCookie(`${state}.${verifier}`, PENDING_TTL)
      }
    })
  }

  if (url.pathname === '/fapi-demo/callback') {
    const held = pendingOf(request)
    const verifier = held?.state === url.searchParams.get('state') ? held?.verifier : undefined
    const spent = { 'set-cookie': pendingCookie('', 0) }
    if (url.searchParams.has('error') || !verifier) {
      return Response.json(
        { error: url.searchParams.get('error') ?? 'no sign-in was started in this browser' },
        { status: 400, headers: spent }
      )
    }
    const token = await post(provider, '/token', {
      grant_type: 'authorization_code',
      code: url.searchParams.get('code') ?? '',
      redirect_uri: `${issuer}/fapi-demo/callback`,
      code_verifier: verifier
    })
    const body = (await token.json()) as Record<string, string>
    if (!token.ok) return Response.json(body, { status: token.status, headers: spent })
    const userinfo = await provider.handle(
      new Request(`${issuer}/userinfo`, {
        headers: { authorization: `DPoP ${body.access_token}`, dpop: await proof('GET', `${issuer}/userinfo`, body.access_token) }
      })
    )
    return Response.json(
      {
        token_type: body.token_type,
        scope: body.scope,
        refresh_token: body.refresh_token ? 'issued; under FAPI 2.0 it does not rotate' : 'not issued',
        id_token: body.id_token && decodeJwt(body.id_token),
        userinfo: await userinfo.json()
      },
      { headers: spent }
    )
  }
  return undefined
}
