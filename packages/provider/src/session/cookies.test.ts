import { describe, expect, test } from 'bun:test'
import { adapter, browserOf, build, challenge, client, ISSUER, REDIRECT, useFlow } from '../test-flow'
import { SESSION_COOKIE } from './session'

useFlow()

describe('malformed cookies are client errors, not 500s', () => {
  test('a cookie that is not percent-decodable is ignored', async () => {
    await adapter.clients.upsert?.(client())
    const params = new URLSearchParams({
      client_id: 'rp',
      redirect_uri: REDIRECT,
      response_type: 'code',
      scope: 'openid',
      code_challenge: challenge,
      code_challenge_method: 'S256'
    })
    const response = await build().handle(
      new Request(`${ISSUER}/authorize?${params}`, { headers: { cookie: `${SESSION_COOKIE}=%E0%A4%A; other=1` } })
    )
    expect(response.status).toBe(303)
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
    const { setCookie } = await provider.interactions.complete(id, { login: { accountId: 'ada' } }, browserOf(first))
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
