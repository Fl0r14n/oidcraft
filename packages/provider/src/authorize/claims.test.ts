import { describe, expect, test } from 'bun:test'
import { decodeJwt } from 'jose'
import type { InteractionResult } from '../interaction'
import { SESSION_COOKIE } from '../session/session'
import {
  adapter,
  authorizeUrl,
  basic,
  browserOf,
  build,
  client,
  drive,
  go,
  ISSUER,
  post,
  provider,
  REDIRECT,
  useFlow,
  verifier
} from '../test-flow'

useFlow()

type Answers = { login?: InteractionResult['login']; consent?: (view: { scopes: string[]; claims: string[] }) => InteractionResult }

/** Authorize, answering each interaction as told; the redirect back to the client, and the session cookie. */
const authorize = async (params: Record<string, string>, answers: Answers = {}, cookie = '') => {
  const views: { kind: string; claims: string[] }[] = []
  let response = await go(authorizeUrl(params), cookie)
  for (let leg = 0; leg < 4; leg++) {
    const location = new URL(response.headers.get('location') as string)
    if (!location.pathname.startsWith('/interaction/')) return { location, cookie, views }
    const id = location.pathname.split('/').pop() as string
    const view = await provider.interactions.find(id)
    views.push(view)
    const answer =
      view.kind === 'login'
        ? { login: answers.login ?? { accountId: 'ada' } }
        : (answers.consent?.(view) ?? { consent: { scopes: view.scopes, claims: view.claims } })
    const done = await provider.interactions.complete(id, answer, browserOf(response))
    if (done.setCookie) cookie = `${SESSION_COOKIE}=${done.setCookie.split('=')[1]?.split(';')[0]}`
    response = await go(done.redirectTo, cookie)
  }
  throw new Error('never reached the client')
}

const redeem = async (location: URL) =>
  (
    await post(
      '/token',
      {
        grant_type: 'authorization_code',
        code: location.searchParams.get('code') as string,
        redirect_uri: REDIRECT,
        code_verifier: verifier
      },
      { authorization: basic() }
    )
  ).json()

const userinfo = async (accessToken: string) =>
  (await provider.handle(new Request(`${ISSUER}/userinfo`, { headers: { authorization: `Bearer ${accessToken}` } }))).json()

const claims = (value: unknown) => ({ scope: 'openid offline_access', claims: JSON.stringify(value) })

// OIDC Core §5.5, FR-C22.
describe('the claims request parameter', () => {
  test('a claim named for userinfo is consented by name and released there, beyond the scopes', async () => {
    const { location, views } = await authorize(claims({ userinfo: { name: null } }))
    expect(views.find(view => view.kind === 'consent')?.claims).toEqual(['name'])
    const tokens = await redeem(location)
    expect(await userinfo(tokens.access_token)).toEqual({ sub: 'ada', name: 'Ada Lovelace' })
    expect(decodeJwt(tokens.id_token)).not.toHaveProperty('name')
  })

  test('a claim named for the ID token is released there, and not at userinfo', async () => {
    const { location } = await authorize(claims({ id_token: { email: { essential: true } } }))
    const tokens = await redeem(location)
    expect(decodeJwt(tokens.id_token).email).toBe('ada@example.com')
    expect(await userinfo(tokens.access_token)).toEqual({ sub: 'ada' })
  })

  // FR-C5: a token for a resource is refused at UserInfo, so what was named for it rides in the ID token.
  test('with a resource, a claim named for userinfo is released in the ID token', async () => {
    drive(build({ resources: [{ uri: 'https://api.example.com' }] }))
    const { location } = await authorize({ ...claims({ userinfo: { name: null } }), resource: 'https://api.example.com' })
    const tokens = await (
      await post(
        '/token',
        {
          grant_type: 'authorization_code',
          code: location.searchParams.get('code') as string,
          redirect_uri: REDIRECT,
          code_verifier: verifier,
          resource: 'https://api.example.com'
        },
        { authorization: basic() }
      )
    ).json()
    expect(decodeJwt(tokens.id_token).name).toBe('Ada Lovelace')
  })

  test('a refreshed access token still releases it', async () => {
    const { location } = await authorize(claims({ userinfo: { name: null } }))
    const { refresh_token } = await redeem(location)
    const refreshed = await (await post('/token', { grant_type: 'refresh_token', refresh_token }, { authorization: basic() })).json()
    expect((await userinfo(refreshed.access_token)).name).toBe('Ada Lovelace')
  })

  test('the consent is remembered, and prompt=none without it is consent_required', async () => {
    const first = await authorize(claims({ userinfo: { name: null } }))
    const again = await authorize({ ...claims({ userinfo: { name: null } }), prompt: 'none' }, {}, first.cookie)
    expect(again.location.searchParams.get('code')).toBeTruthy()

    const more = await authorize({ ...claims({ userinfo: { email: null } }), prompt: 'none' }, {}, first.cookie)
    expect(more.location.searchParams.get('error')).toBe('consent_required')
    expect((await adapter.grants.findByAccountAndClient('ada', 'rp'))?.claims).toEqual(['name'])
  })

  test('a claim a requested scope releases asks for nothing more', async () => {
    const { views } = await authorize({ scope: 'openid profile', claims: JSON.stringify({ userinfo: { name: null } }) })
    expect(views.find(view => view.kind === 'consent')?.claims).toEqual([])
  })

  // A client's scopes bound what it may learn; naming a claim one by one does not get around them.
  test('a claim only a scope this client may not request releases is ignored', async () => {
    await adapter.clients.upsert?.(client({ scopes: ['openid', 'profile', 'offline_access'] }))
    const { location, views } = await authorize(claims({ userinfo: { email: null }, id_token: { email: null } }))
    expect(views.find(view => view.kind === 'consent')?.claims).toEqual([])
    const tokens = await redeem(location)
    expect(await userinfo(tokens.access_token)).not.toHaveProperty('email')
    expect(decodeJwt(tokens.id_token)).not.toHaveProperty('email')
  })

  test('a refresh narrowed away from a scope stops releasing what only that scope covered', async () => {
    const { location } = await authorize({ scope: 'openid email offline_access', claims: JSON.stringify({ userinfo: { email: null } }) })
    const { refresh_token } = await redeem(location)
    const narrowed = await (
      await post('/token', { grant_type: 'refresh_token', refresh_token, scope: 'openid offline_access' }, { authorization: basic() })
    ).json()
    expect(await userinfo(narrowed.access_token)).not.toHaveProperty('email')
  })

  test('a claim the configuration does not list is ignored', async () => {
    const { location, views } = await authorize(claims({ userinfo: { favourite_colour: { essential: true } } }))
    expect(views.find(view => view.kind === 'consent')?.claims).toEqual([])
    expect(location.searchParams.get('code')).toBeTruthy()
  })

  test('consent must name every claim asked for, and none it was not', async () => {
    await expect(
      authorize(claims({ userinfo: { name: null, email: null } }), {
        consent: view => ({ consent: { scopes: view.scopes, claims: ['name'] } })
      })
    ).rejects.toMatchObject({ code: 'invalid_request', description: expect.stringContaining('leaves out email') })
    await expect(
      authorize(claims({ userinfo: { name: null } }), {
        consent: view => ({ consent: { scopes: view.scopes, claims: ['name', 'email'] } })
      })
    ).rejects.toMatchObject({ code: 'invalid_request', description: expect.stringContaining('did not ask for') })
  })

  test('a malformed request is refused to the client', async () => {
    for (const value of ['not json', '[]', '{"userinfo":[]}', '{"id_token":{"acr":{"essential":"yes"}}}']) {
      const { location } = await authorize({ claims: value })
      expect({ value, error: location.searchParams.get('error') }).toEqual({ value, error: 'invalid_request' })
    }
  })

  test('is advertised', async () => {
    const metadata = await (await provider.handle(new Request(`${ISSUER}/.well-known/openid-configuration`))).json()
    expect(metadata.claims_parameter_supported).toBe(true)
  })
})

// §5.5.1.1: an essential acr with values is a requirement on the login.
describe('an essential acr', () => {
  const acr = (essential: boolean) => claims({ id_token: { acr: { essential, values: ['mfa', 'hwk'] } } })

  test('a login that reaches it issues a code, and the ID token says so', async () => {
    const { location, views } = await authorize(acr(true), { login: { accountId: 'ada', acr: 'mfa' } })
    expect(views[0]).toMatchObject({ kind: 'login', acrValues: ['mfa', 'hwk'] })
    expect(decodeJwt((await redeem(location)).id_token).acr).toBe('mfa')
  })

  test('a login that does not is a failed authentication', async () => {
    const { location } = await authorize(acr(true), { login: { accountId: 'ada', acr: 'pwd' } })
    expect(location.searchParams.get('error')).toBe('access_denied')
  })

  test('a session below it signs in again, and prompt=none is login_required', async () => {
    const weak = await authorize({ scope: 'openid' }, { login: { accountId: 'ada', acr: 'pwd' } })
    const none = await authorize({ ...acr(true), prompt: 'none' }, {}, weak.cookie)
    expect(none.location.searchParams.get('error')).toBe('login_required')
    const stepped = await authorize(acr(true), { login: { accountId: 'ada', acr: 'hwk' } }, weak.cookie)
    expect(stepped.views[0]?.kind).toBe('login')
    expect(stepped.location.searchParams.get('code')).toBeTruthy()
  })

  test('a voluntary one is shown to the login, never enforced', async () => {
    const { location, views } = await authorize(acr(false), { login: { accountId: 'ada', acr: 'pwd' } })
    expect(views[0]).toMatchObject({ kind: 'login', acrValues: ['mfa', 'hwk'] })
    expect(location.searchParams.get('code')).toBeTruthy()
  })
})

// §5.5.1: a requested sub is answered for that person or no one.
describe('a requested sub', () => {
  const as = (sub: string) => claims({ id_token: { sub: { value: sub } } })

  test('another session is asked to sign in, and prompt=none is login_required', async () => {
    const signedIn = await authorize({ scope: 'openid' })
    const none = await authorize({ ...as('bob'), prompt: 'none' }, {}, signedIn.cookie)
    expect(none.location.searchParams.get('error')).toBe('login_required')
    const bob = await authorize(as('bob'), { login: { accountId: 'bob' } }, signedIn.cookie)
    expect(bob.views[0]?.kind).toBe('login')
    expect(decodeJwt((await redeem(bob.location)).id_token).sub).toBe('bob')
  })

  test('a login as someone else is refused', async () => {
    const { location } = await authorize(as('bob'), { login: { accountId: 'ada' } })
    expect(location.searchParams.get('error')).toBe('access_denied')
  })

  test('the session it names is answered without a login', async () => {
    const signedIn = await authorize({ scope: 'openid offline_access' })
    const again = await authorize({ ...as('ada'), prompt: 'none' }, {}, signedIn.cookie)
    expect(again.location.searchParams.get('code')).toBeTruthy()
  })
})
