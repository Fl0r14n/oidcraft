import { beforeEach, describe, expect, test } from 'bun:test'
import { memoryAdapter } from './adapters/memory'
import type { Adapter, Client, ExchangePolicy } from './index'
import { createProvider, type Provider } from './provider'
import { base64url, sha256, token } from './random'
import { SESSION_COOKIE } from './session'

const ISSUER = 'https://op.example.com'
const REDIRECT = 'https://rp.example.com/cb'
const SECRET = 'shhh-a-long-enough-secret'

const client = (over: Partial<Client> = {}): Client => ({
  clientId: 'rp',
  clientSecret: SECRET,
  redirectUris: [REDIRECT],
  grantTypes: ['authorization_code', 'refresh_token', 'urn:ietf:params:oauth:grant-type:token-exchange'],
  responseTypes: ['code'],
  scopes: ['openid', 'profile', 'orders'],
  tokenEndpointAuthMethod: 'client_secret_basic',
  createdAt: new Date(),
  updatedAt: new Date(),
  ...over
})

const accounts = {
  async find(accountId: string) {
    return { accountId, claims: {} }
  },
  async claims() {
    return {}
  }
}

let adapter: Adapter
let verifier: string
let challenge: string

const basic = (id = 'rp', secret = SECRET) => `Basic ${btoa(`${id}:${secret}`)}`

beforeEach(async () => {
  adapter = await memoryAdapter({ accounts })
  await adapter.clients.create?.(client())
  verifier = token(32) + token(32)
  challenge = base64url(await sha256(verifier))
})

// `orders` has to be declared here too: a client may only request scopes the provider knows about.
const build = (over: Parameters<typeof createProvider>[0] extends infer T ? Partial<T> : never = {}) =>
  createProvider({
    issuer: ISSUER,
    adapter,
    interactionUrl: `${ISSUER}/interaction`,
    scopes: ['openid', 'profile', 'email', 'offline_access', 'orders'],
    ...over
  } as Parameters<typeof createProvider>[0])

const post = (provider: Provider, path: string, body: Record<string, string>, headers: Record<string, string> = {}) =>
  provider.handle(
    new Request(`${ISSUER}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers },
      body: new URLSearchParams(body).toString()
    })
  )

const tokensFor = async (provider: Provider, extra: Record<string, string> = {}) => {
  const params = new URLSearchParams({
    client_id: 'rp',
    redirect_uri: REDIRECT,
    response_type: 'code',
    scope: 'openid profile orders',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    ...extra
  })
  let response = await provider.handle(new Request(`${ISSUER}/authorize?${params}`))
  let cookie = ''
  for (let leg = 0; leg < 4; leg++) {
    const location = new URL(response.headers.get('location') as string)
    if (!location.pathname.startsWith('/interaction/')) {
      const code = location.searchParams.get('code') as string
      return (
        await post(
          provider,
          '/token',
          { grant_type: 'authorization_code', code, redirect_uri: REDIRECT, code_verifier: verifier },
          { authorization: basic() }
        )
      ).json()
    }
    const id = location.pathname.split('/').pop() as string
    const view = await provider.interactions.find(id)
    const done = await provider.interactions.complete(
      id,
      view.kind === 'login' ? { login: { accountId: 'ada', acr: 'pwd' } } : { consent: { scopes: view.scopes } }
    )
    if (done.setCookie) cookie = `${SESSION_COOKIE}=${done.setCookie.split('=')[1]?.split(';')[0]}`
    response = await provider.handle(new Request(done.redirectTo, { headers: cookie ? { cookie } : {} }))
  }
  throw new Error('never reached the redirect')
}

const ACCESS = 'urn:ietf:params:oauth:token-type:access_token'

describe('token exchange', () => {
  // A library cannot know which impersonation a deployment considers legitimate.
  test('is refused outright without a policy', async () => {
    const provider = build()
    const issued = await tokensFor(provider)
    const response = await post(
      provider,
      '/token',
      { grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange', subject_token: issued.access_token, subject_token_type: ACCESS },
      { authorization: basic() }
    )
    const body = await response.json()
    expect(body.error).toBe('unsupported_grant_type')
    expect(body.error_description).toContain('exchangePolicy')
  })

  test('is not advertised without a policy, and is with one', async () => {
    const without = await (await build().handle(new Request(`${ISSUER}/.well-known/openid-configuration`))).json()
    expect(without.grant_types_supported).not.toContain('urn:ietf:params:oauth:grant-type:token-exchange')

    const policy: ExchangePolicy = () => undefined
    const with_ = await (await build({ exchangePolicy: policy }).handle(new Request(`${ISSUER}/.well-known/openid-configuration`))).json()
    expect(with_.grant_types_supported).toContain('urn:ietf:params:oauth:grant-type:token-exchange')
  })

  const allowing: ExchangePolicy = ({ subjectToken, requested }) => ({
    accountId: subjectToken.accountId as string,
    scopes: requested.scopes.length ? requested.scopes : ((subjectToken.payload.scopes as string[]) ?? []),
    resource: requested.resource
  })

  test('exchanges a subject token for a narrower one', async () => {
    const provider = build({ exchangePolicy: allowing })
    const issued = await tokensFor(provider)
    const response = await post(
      provider,
      '/token',
      {
        grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
        subject_token: issued.access_token,
        subject_token_type: ACCESS,
        scope: 'orders',
        resource: 'https://api.example.com'
      },
      { authorization: basic() }
    )
    expect(response.status).toBe(200)
    const body = await response.json()
    expect(body.access_token).toBeTruthy()
    expect(body.issued_token_type).toBe(ACCESS)
    expect(body.scope).toBe('orders')
  })

  // RFC 8693 §2.1: widening is an escalation, not an exchange.
  test('cannot widen beyond what the subject token held', async () => {
    const widening: ExchangePolicy = ({ subjectToken }) => ({ accountId: subjectToken.accountId as string, scopes: ['openid', 'admin'] })
    const provider = build({ exchangePolicy: widening })
    const issued = await tokensFor(provider)
    const response = await post(
      provider,
      '/token',
      { grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange', subject_token: issued.access_token, subject_token_type: ACCESS },
      { authorization: basic() }
    )
    expect((await response.json()).error).toBe('invalid_scope')
  })

  test('a refused exchange is invalid_target', async () => {
    const provider = build({ exchangePolicy: () => undefined })
    const issued = await tokensFor(provider)
    const response = await post(
      provider,
      '/token',
      { grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange', subject_token: issued.access_token, subject_token_type: ACCESS },
      { authorization: basic() }
    )
    expect((await response.json()).error).toBe('invalid_target')
  })

  test('an unknown subject token is refused', async () => {
    const provider = build({ exchangePolicy: allowing })
    const response = await post(
      provider,
      '/token',
      { grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange', subject_token: 'nope', subject_token_type: ACCESS },
      { authorization: basic() }
    )
    expect((await response.json()).error).toBe('invalid_grant')
  })

  test('an actor_token without its type is refused', async () => {
    const provider = build({ exchangePolicy: allowing })
    const issued = await tokensFor(provider)
    const response = await post(
      provider,
      '/token',
      {
        grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
        subject_token: issued.access_token,
        subject_token_type: ACCESS,
        actor_token: issued.access_token
      },
      { authorization: basic() }
    )
    expect((await response.json()).error_description).toContain('actor_token_type')
  })

  // RFC 8693 §4.1: a resource server must be able to tell delegation from the real thing.
  test('the acting party is recorded on the issued token', async () => {
    const delegating: ExchangePolicy = ({ subjectToken, client: caller }) => ({
      accountId: subjectToken.accountId as string,
      scopes: (subjectToken.payload.scopes as string[]) ?? [],
      actor: { clientId: caller.clientId }
    })
    const provider = build({ exchangePolicy: delegating })
    const issued = await tokensFor(provider)
    const body = await (
      await post(
        provider,
        '/token',
        { grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange', subject_token: issued.access_token, subject_token_type: ACCESS },
        { authorization: basic() }
      )
    ).json()
    const stored = await adapter.artifacts.find('access_token', body.access_token)
    expect(stored?.payload.act).toEqual({ client_id: 'rp' })
  })
})

describe('rich authorization requests', () => {
  const detail = JSON.stringify([{ type: 'payment', amount: '42.00', currency: 'EUR' }])

  test('an undeclared type is refused rather than silently granted', async () => {
    const provider = build()
    const response = await provider.handle(
      new Request(
        `${ISSUER}/authorize?${new URLSearchParams({
          client_id: 'rp',
          redirect_uri: REDIRECT,
          response_type: 'code',
          scope: 'openid',
          code_challenge: challenge,
          code_challenge_method: 'S256',
          authorization_details: detail
        })}`
      )
    )
    const params = new URL(response.headers.get('location') as string).searchParams
    expect(params.get('error')).toBe('invalid_authorization_details')
  })

  test('a declared type flows through to the issued token', async () => {
    const provider = build({ authorizationDetailTypes: ['payment'] })
    const issued = await tokensFor(provider, { authorization_details: detail })
    expect(issued.authorization_details).toEqual([{ type: 'payment', amount: '42.00', currency: 'EUR' }])
  })

  test('malformed details are refused', async () => {
    const provider = build({ authorizationDetailTypes: ['payment'] })
    for (const bad of ['not json', '{}', '[]', '[{"amount":1}]']) {
      const response = await provider.handle(
        new Request(
          `${ISSUER}/authorize?${new URLSearchParams({
            client_id: 'rp',
            redirect_uri: REDIRECT,
            response_type: 'code',
            scope: 'openid',
            code_challenge: challenge,
            code_challenge_method: 'S256',
            authorization_details: bad
          })}`
        )
      )
      const params = new URL(response.headers.get('location') as string).searchParams
      expect({ bad, error: params.get('error') }).toEqual({ bad, error: 'invalid_authorization_details' })
    }
  })

  test('declared types are advertised', async () => {
    const metadata = await (
      await build({ authorizationDetailTypes: ['payment'] }).handle(new Request(`${ISSUER}/.well-known/openid-configuration`))
    ).json()
    expect(metadata.authorization_details_types_supported).toEqual(['payment'])
  })
})

describe('step-up authentication', () => {
  // RFC 9470: honouring an acr means re-authenticating, not issuing a token that fails to meet it.
  test('an acr the session cannot satisfy forces a fresh login', async () => {
    const provider = build()
    const issued = await tokensFor(provider)
    expect(issued.access_token).toBeTruthy()

    const session = (await adapter.sessions.findByAccount('ada'))[0]
    const cookie = `${SESSION_COOKIE}=${session?.id}`
    const response = await provider.handle(
      new Request(
        `${ISSUER}/authorize?${new URLSearchParams({
          client_id: 'rp',
          redirect_uri: REDIRECT,
          response_type: 'code',
          scope: 'openid',
          code_challenge: challenge,
          code_challenge_method: 'S256',
          acr_values: 'mfa'
        })}`,
        { headers: { cookie } }
      )
    )
    expect(response.headers.get('location')).toContain('/interaction/')
    const view = await provider.interactions.find(new URL(response.headers.get('location') as string).pathname.split('/').pop() as string)
    expect(view.kind).toBe('login')
    expect(view.acrValues).toEqual(['mfa'])
  })

  test('an acr the session already meets does not', async () => {
    const provider = build()
    await tokensFor(provider)
    const session = (await adapter.sessions.findByAccount('ada'))[0]
    const response = await provider.handle(
      new Request(
        `${ISSUER}/authorize?${new URLSearchParams({
          client_id: 'rp',
          redirect_uri: REDIRECT,
          response_type: 'code',
          scope: 'openid',
          code_challenge: challenge,
          code_challenge_method: 'S256',
          acr_values: 'pwd'
        })}`,
        { headers: { cookie: `${SESSION_COOKIE}=${session?.id}` } }
      )
    )
    expect(new URL(response.headers.get('location') as string).searchParams.get('code')).toBeTruthy()
  })

  test('prompt=none with an unmet acr is login_required, not a weaker token', async () => {
    const provider = build()
    await tokensFor(provider)
    const session = (await adapter.sessions.findByAccount('ada'))[0]
    const response = await provider.handle(
      new Request(
        `${ISSUER}/authorize?${new URLSearchParams({
          client_id: 'rp',
          redirect_uri: REDIRECT,
          response_type: 'code',
          scope: 'openid',
          code_challenge: challenge,
          code_challenge_method: 'S256',
          acr_values: 'mfa',
          prompt: 'none'
        })}`,
        { headers: { cookie: `${SESSION_COOKIE}=${session?.id}` } }
      )
    )
    expect(new URL(response.headers.get('location') as string).searchParams.get('error')).toBe('login_required')
  })
})

describe('resuming an interaction', () => {
  // The rebuild used to be a hand-maintained list of parameters, so anything not on it was dropped
  // between the first authorization request and the resumed one. This is the regression test.
  test('replays every parameter across the interaction round trip', async () => {
    const provider = build({ authorizationDetailTypes: ['payment'] })
    const params = new URLSearchParams({
      client_id: 'rp',
      redirect_uri: REDIRECT,
      response_type: 'code',
      scope: 'openid profile',
      state: 'st',
      nonce: 'nc',
      code_challenge: challenge,
      code_challenge_method: 'S256',
      ui_locales: 'de',
      login_hint: 'ada@example.test',
      authorization_details: JSON.stringify([{ type: 'payment', amount: '1.00' }]),
      prompt: 'login'
    })

    const first = await provider.handle(new Request(`${ISSUER}/authorize?${params}`))
    const id = new URL(first.headers.get('location') as string).pathname.split('/').pop() as string
    const { redirectTo } = await provider.interactions.complete(id, { login: { accountId: 'ada' } })

    const resumed = new URL(redirectTo).searchParams
    for (const [name, value] of params) {
      if (name === 'prompt') continue
      expect({ name, value: resumed.get(name) }).toEqual({ name, value })
    }
    // Otherwise the interaction that has just been satisfied is demanded again, forever.
    expect(resumed.get('prompt')).toBeNull()
  })
})
