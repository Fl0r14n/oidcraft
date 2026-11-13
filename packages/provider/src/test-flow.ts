import { beforeEach } from 'bun:test'
import { hashClientSecret } from '@oidcraft/adapter'
import { memoryAdapter } from '@oidcraft/adapter/memory'
import { randomString, sha256 } from '@oidcraft/core'
import { base64url } from 'jose'
import type { ProviderConfig } from './config'
import type { Adapter, Client, RequestContext } from './index'
import { createProvider, type Provider } from './provider'
import { SESSION_COOKIE } from './session/session'

export const ISSUER = 'https://op.example.com'
export const REDIRECT = 'https://rp.example.com/cb'
export const SECRET = 'shhh-a-long-enough-secret'
const SECRET_HASH = await hashClientSecret(SECRET)

/** The browser-binding cookie the redirect to an interaction set, as the browser would send it back (FR-I2). */
export const browserOf = (response: Response) => response.headers.get('set-cookie')?.split(';')[0] ?? null

export const client = (over: Partial<Client> = {}): Client => ({
  clientId: 'rp',
  clientSecretHash: SECRET_HASH,
  redirectUris: [REDIRECT],
  grantTypes: ['authorization_code', 'refresh_token'],
  responseTypes: ['code'],
  scopes: ['openid', 'profile', 'email', 'offline_access'],
  tokenEndpointAuthMethod: 'client_secret_basic',
  createdAt: new Date(),
  updatedAt: new Date(),
  ...over
})

const accounts = {
  async find(accountId: string) {
    return accountId === 'ghost' ? undefined : { accountId, claims: {} }
  },
  async claims(_accountId: string, scopes: string[], named: string[]) {
    const all = { name: 'Ada Lovelace', email: 'ada@example.com' }
    return Object.fromEntries(Object.entries(all).filter(([name]) => scopes.includes('profile') || named.includes(name)))
  }
}

export let adapter: Adapter
export let provider: Provider
export let verifier: string
export let challenge: string

/** A fresh in-memory adapter, PKCE pair and default provider before each test, with client `rp` registered. */
export const useFlow = () =>
  beforeEach(async () => {
    adapter = await memoryAdapter({ accounts: { ...accounts } })
    await adapter.clients.upsert?.(client())
    provider = build()
    verifier = randomString() + randomString()
    challenge = base64url.encode(await sha256(verifier))
  })

/** Swaps the provider `go`, `post` and `loginAndConsent` drive, for a test that needs its own. */
export const drive = (next: Provider) => {
  provider = next
}

export const build = (over: Partial<ProviderConfig> = {}) =>
  createProvider({ issuer: ISSUER, adapter, interactionUrl: `${ISSUER}/interaction`, ...over })

export const basic = (id = 'rp', secret = SECRET) => `Basic ${btoa(`${id}:${secret}`)}`

export const authorizeUrl = (over: Record<string, string> = {}) => {
  const params = new URLSearchParams({
    client_id: 'rp',
    redirect_uri: REDIRECT,
    response_type: 'code',
    scope: 'openid profile offline_access',
    state: 'xyz',
    nonce: 'n-0S6_WzA2Mj',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    ...over
  })
  return `${ISSUER}/authorize?${params}`
}

export const go = (url: string, cookie?: string) => provider.handle(new Request(url, { headers: cookie ? { cookie } : {} }))

export const post = (path: string, body: Record<string, string>, headers: Record<string, string> = {}) =>
  provider.handle(
    new Request(`${ISSUER}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers },
      body: new URLSearchParams(body).toString()
    })
  )

/** Drives the browser legs a real user would: authorize -> login -> consent -> code. */
export const loginAndConsent = async (over: Record<string, string> = {}) => {
  const first = await go(authorizeUrl(over))
  const loginId = new URL(first.headers.get('location') as string).pathname.split('/').pop() as string

  const login = await provider.interactions.complete(loginId, { login: { accountId: 'ada' } }, browserOf(first))
  const cookie = `${SESSION_COOKIE}=${(login.setCookie as string).split('=')[1]?.split(';')[0]}`

  const second = await go(login.redirectTo, cookie)
  const consentId = new URL(second.headers.get('location') as string).pathname.split('/').pop() as string

  const consent = await provider.interactions.complete(
    consentId,
    { consent: { scopes: ['openid', 'profile', 'offline_access'] } },
    browserOf(second)
  )
  const third = await go(consent.redirectTo, cookie)
  return { location: new URL(third.headers.get('location') as string), cookie }
}

/** Every leg from authorize to a token response on `on`, answering each interaction as it comes. */
export const tokensFor = async (
  on: Provider,
  clientId = 'rp',
  context?: Partial<RequestContext>,
  { session, scope = 'openid profile' }: { session?: string | undefined; scope?: string } = {}
) => {
  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: REDIRECT,
    response_type: 'code',
    scope,
    code_challenge: challenge,
    code_challenge_method: 'S256'
  })
  let secret = session
  let cookie = session ? `${SESSION_COOKIE}=${session}` : ''
  let response = await on.handle(new Request(`${ISSUER}/authorize?${params}`, { headers: cookie ? { cookie } : {} }))
  for (let leg = 0; leg < 4; leg++) {
    const location = new URL(response.headers.get('location') as string)
    if (!location.pathname.startsWith('/interaction/')) {
      const code = location.searchParams.get('code') as string
      const isPublic = (await adapter.clients.find(clientId))?.tokenEndpointAuthMethod === 'none'
      const issued = await (
        await on.handle(
          new Request(`${ISSUER}/token`, {
            method: 'POST',
            headers: { 'content-type': 'application/x-www-form-urlencoded', ...(!isPublic && { authorization: basic(clientId) }) },
            body: new URLSearchParams({
              grant_type: 'authorization_code',
              ...(isPublic && { client_id: clientId }),
              code,
              redirect_uri: REDIRECT,
              code_verifier: verifier
            }).toString()
          }),
          context
        )
      ).json()
      return { ...issued, secret }
    }
    const id = location.pathname.split('/').pop() as string
    const view = await on.interactions.find(id)
    const done = await on.interactions.complete(
      id,
      view.kind === 'login' ? { login: { accountId: 'ada', acr: 'pwd' } } : { consent: { scopes: view.scopes } },
      browserOf(response)
    )
    if (done.setCookie) {
      secret = done.setCookie.split('=')[1]?.split(';')[0]
      cookie = `${SESSION_COOKIE}=${secret}`
    }
    response = await on.handle(new Request(done.redirectTo, { headers: cookie ? { cookie } : {} }))
  }
  throw new Error('never reached the redirect')
}

/** RP-initiated logout as a relying party sends it: with the ID token it was issued (OIDC RP-Initiated Logout 1.0 §2). */
export const endSession = (on: Provider, secret: string | undefined, idToken: string) =>
  on.handle(
    new Request(`${ISSUER}/session/end?${new URLSearchParams({ id_token_hint: idToken })}`, {
      headers: { cookie: `${SESSION_COOKIE}=${secret}` }
    })
  )
