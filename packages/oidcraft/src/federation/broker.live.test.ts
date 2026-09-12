/// <reference types="bun" />
import { afterAll, describe, expect, test } from 'bun:test'
import { memoryAdapter } from '../adapters/memory'
import { createProvider } from '../provider'
import { SESSION_COOKIE } from '../session'
import { createBroker } from './broker'
import { linkIdentity } from './link'

/**
 * The upstream is a second oidcraft instance (ARCHITECTURE.md §10). Brokering to ourselves
 * exercises both legs for real — discovery, PKCE, the code exchange, the ID token — without
 * depending on Google being up.
 */
const upstreamAdapter = await memoryAdapter({
  accounts: {
    async find(accountId) {
      return { accountId, claims: {} }
    },
    async claims(accountId, scopes) {
      return scopes.includes('email') ? { email: `${accountId}@upstream.test`, email_verified: true, name: accountId } : {}
    }
  }
})

const server = Bun.serve({ port: 0, fetch: request => upstream.handle(request) })
const ISSUER = `http://127.0.0.1:${server.port}`
const CALLBACK = 'http://127.0.0.1:9999/federation/callback'

const upstream = createProvider({ issuer: ISSUER, adapter: upstreamAdapter, interactionUrl: `${ISSUER}/interaction` })

await upstreamAdapter.clients.create?.({
  clientId: 'broker',
  clientSecret: 'a-long-enough-upstream-secret',
  redirectUris: [CALLBACK],
  grantTypes: ['authorization_code'],
  responseTypes: ['code'],
  scopes: ['openid', 'email', 'profile'],
  // openid-client v6 sends client_id/client_secret in the body by default, not a Basic header —
  // measured 2026-09-12. The core enforces the method a client registered, so this must match.
  tokenEndpointAuthMethod: 'client_secret_post',
  createdAt: new Date(),
  updatedAt: new Date()
})

afterAll(() => server.stop(true))

const downstream = await memoryAdapter()
const broker = createBroker({
  adapter: downstream,
  callbackUri: CALLBACK,
  allowInsecure: true,
  providers: [
    { id: 'self', issuer: ISSUER, clientId: 'broker', clientSecret: 'a-long-enough-upstream-secret', scopes: ['openid', 'email'] }
  ]
})

/**
 * Drives whatever the upstream asks for, rather than assuming a fixed number of legs: consent is
 * remembered (FR-I4), so a second sign-in for the same account and client skips it entirely.
 */
const authenticateUpstream = async (authorizationUrl: string) => {
  let response = await upstream.handle(new Request(authorizationUrl))
  let cookie = ''

  for (let leg = 0; leg < 4; leg++) {
    const location = new URL(response.headers.get('location') as string)
    if (!location.pathname.startsWith('/interaction/')) return location

    const id = location.pathname.split('/').pop() as string
    const view = await upstream.interactions.find(id)
    const outcome = view.kind === 'login' ? { login: { accountId: 'ada' } } : { consent: { scopes: view.scopes } }

    const completed = await upstream.interactions.complete(id, outcome)
    if (completed.setCookie) cookie = `${SESSION_COOKIE}=${completed.setCookie.split('=')[1]?.split(';')[0]}`
    response = await upstream.handle(new Request(completed.redirectTo, { headers: cookie ? { cookie } : {} }))
  }
  throw new Error('the upstream kept asking for interactions')
}

describe('brokering to a live upstream', () => {
  test('completes both legs and yields a mapped identity', async () => {
    const { url } = await broker.start('downstream-interaction-1', 'self')
    expect(url).toStartWith(`${ISSUER}/authorize`)
    expect(new URL(url).searchParams.get('code_challenge_method')).toBe('S256')

    const callback = await authenticateUpstream(url)
    const { interactionId, identity } = await broker.complete(callback)

    // FR-F3: the handoff is what makes this a resume of one downstream request.
    expect(interactionId).toBe('downstream-interaction-1')
    expect(identity.provider).toBe('self')
    expect(identity.subject).toBe('ada')
    // FR-F7: mapped, not passed through wholesale.
    expect(identity.email).toBe('ada@upstream.test')
    expect(identity.claims).not.toHaveProperty('sub')
    expect(identity.claims).not.toHaveProperty('iss')
    // FR-F6: provenance from the upstream.
    expect(identity.authTime).toBeInstanceOf(Date)
    // FR-F10: not retained unless the provider opted in.
    expect(identity.upstreamTokens).toBeUndefined()
  })

  test('the handoff is single-use, so a replayed callback is refused', async () => {
    const { url } = await broker.start('downstream-interaction-2', 'self')
    const callback = await authenticateUpstream(url)
    await broker.complete(callback)
    expect(broker.complete(callback)).rejects.toThrow(/did not start here/)
  })

  test('a callback whose state was never issued is refused', async () => {
    const forged = new URL(`${CALLBACK}?code=whatever&state=never-issued`)
    expect(broker.complete(forged)).rejects.toThrow(/did not start here/)
  })

  test('a callback with no state at all is refused', async () => {
    expect(broker.complete(new URL(`${CALLBACK}?code=whatever`))).rejects.toThrow(/no state/)
  })

  test('the brokered identity links to a local account', async () => {
    const { url } = await broker.start('downstream-interaction-3', 'self')
    const { identity } = await broker.complete(await authenticateUpstream(url))

    const first = await linkIdentity(downstream, identity, { createAccount: async () => 'local-1' })
    expect(first).toEqual({ accountId: 'local-1', created: true })

    // The second time the same upstream subject arrives it must resolve to the same local account.
    const { url: again } = await broker.start('downstream-interaction-4', 'self')
    const { identity: repeat } = await broker.complete(await authenticateUpstream(again))
    expect(await linkIdentity(downstream, repeat, { createAccount: async () => 'local-2' })).toEqual({
      accountId: 'local-1',
      created: false
    })
  })

  test('retainTokens is what decides whether upstream tokens are kept', async () => {
    const keeping = createBroker({
      adapter: downstream,
      callbackUri: CALLBACK,
      allowInsecure: true,
      providers: [
        {
          id: 'self',
          issuer: ISSUER,
          clientId: 'broker',
          clientSecret: 'a-long-enough-upstream-secret',
          scopes: ['openid', 'email'],
          retainTokens: true
        }
      ]
    })
    const { url } = await keeping.start('downstream-interaction-5', 'self')
    const { identity } = await keeping.complete(await authenticateUpstream(url))
    expect(identity.upstreamTokens?.accessToken).toBeTruthy()
  })

  test('an unknown provider id is refused', async () => {
    expect(broker.start('x', 'nope')).rejects.toThrow(/unknown upstream provider/)
  })
})
