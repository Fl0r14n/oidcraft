import { beforeEach, describe, expect, test } from 'bun:test'
import { memoryAdapter } from '@oidcraft/adapter/memory'
import { decodeProtectedHeader } from 'jose'
import { detailsConsentId } from './authorize/authorization'
import type { Adapter, Client, LogoutNotification } from './index'
import { createProvider } from './provider'
import { pairwiseSubject } from './token/subjects'

const ISSUER = 'https://op.example.com'

const client = (over: Partial<Client> = {}): Client => ({
  clientId: 'rp',
  clientSecret: 'a-long-enough-client-secret',
  redirectUris: ['https://rp.example.com/cb'],
  grantTypes: ['authorization_code'],
  responseTypes: ['code'],
  scopes: ['openid'],
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

beforeEach(async () => {
  adapter = await memoryAdapter({ accounts })
})

const build = (over: Record<string, unknown> = {}) =>
  createProvider({ issuer: ISSUER, adapter, interactionUrl: `${ISSUER}/interaction`, ...over } as Parameters<typeof createProvider>[0])

describe('UserInfo answers a bad token as RFC 6750 names it', () => {
  test('invalid_token in the body as in the challenge', async () => {
    const response = await build().handle(new Request(`${ISSUER}/userinfo`, { headers: { authorization: 'Bearer nope' } }))
    expect(response.status).toBe(401)
    expect(response.headers.get('www-authenticate')).toContain('error="invalid_token"')
    expect((await response.json()).error).toBe('invalid_token')
  })

  test('no token at all is invalid_request', async () => {
    const response = await build().handle(new Request(`${ISSUER}/userinfo`))
    expect((await response.json()).error).toBe('invalid_request')
  })
})

describe('FR-C18: a derived identifier has one input it can come from', () => {
  test('a dot moving between the sector and the account changes the pairwise subject', async () => {
    expect(await pairwiseSubject('c', 'a.b', 'salt')).not.toBe(await pairwiseSubject('b.c', 'a', 'salt'))
  })

  test('the salt changes it, and the same inputs repeat it', async () => {
    expect(await pairwiseSubject('ada', 'rp.example.com', 'one')).not.toBe(await pairwiseSubject('ada', 'rp.example.com', 'two'))
    expect(await pairwiseSubject('ada', 'rp.example.com', 'one')).toBe(await pairwiseSubject('ada', 'rp.example.com', 'one'))
  })

  test('a newline moving between the account and the client changes the details-consent id', async () => {
    const details = [{ type: 'payment' }]
    expect(await detailsConsentId('a\nb', 'c', details)).not.toBe(await detailsConsentId('a', 'b\nc', details))
  })
})

describe('FR-C11: a logout token is signed as the client asked its ID tokens to be', () => {
  test("the client's id_token_signed_response_alg, not the provider's first key", async () => {
    let delivered: LogoutNotification[] = []
    await adapter.clients.upsert?.(client({ idTokenSignedResponseAlg: 'RS256', backchannelLogoutUri: 'https://rp.example.com/out' }))
    const provider = build({
      onLogout: (notifications: LogoutNotification[]) => {
        delivered = notifications
      }
    })
    await adapter.sessions.upsert({
      id: 's1',
      accountId: 'ada',
      authTime: new Date(),
      clients: ['rp'],
      expiresAt: new Date(Date.now() + 60_000)
    })
    await provider.management.sessions.destroy('s1')
    expect(decodeProtectedHeader(delivered[0]?.logoutToken as string).alg).toBe('RS256')
  })
})

describe('the session cookie belongs to one issuer', () => {
  const signIn = async (issuer: string) => {
    await adapter.clients.upsert?.(client())
    const provider = build({ issuer, interactionUrl: `${issuer}/interaction` })
    const params = new URLSearchParams({
      client_id: 'rp',
      redirect_uri: 'https://rp.example.com/cb',
      response_type: 'code',
      scope: 'openid',
      code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
      code_challenge_method: 'S256'
    })
    const first = await provider.handle(new Request(`${issuer}/authorize?${params}`))
    const id = (first.headers.get('location') as string).split('/').pop() as string
    const { setCookie } = await provider.interactions.complete(id, { login: { accountId: 'ada' } })
    const pair = (setCookie as string).split(';')[0] as string
    return { provider, name: pair.split('=')[0] as string, pair }
  }

  test('an issuer at the root keeps the plain name', async () => {
    expect((await signIn(ISSUER)).name).toBe('oidcraft.sid')
  })

  test('two issuers on one host do not share a cookie, and each reads its own', async () => {
    const a = await signIn(`${ISSUER}/a`)
    const b = await signIn(`${ISSUER}/b`)
    expect(a.name).not.toBe(b.name)
    const cookie = `${a.pair}; ${b.pair}`
    expect((await a.provider.session(new Request(ISSUER, { headers: { cookie } })))?.accountId).toBe('ada')
    expect((await b.provider.session(new Request(ISSUER, { headers: { cookie } })))?.accountId).toBe('ada')
    expect(a.pair.split('=')[1]).not.toBe(b.pair.split('=')[1])
  })
})
