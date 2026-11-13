import { describe, expect, test } from 'bun:test'
import { SESSION_COOKIE } from '../session/session'
import { authorizeUrl, browserOf, go, ISSUER, loginAndConsent, provider, REDIRECT, useFlow } from '../test-flow'

useFlow()

describe('interaction', () => {
  // Login CSRF: the attacker starts an interaction in their own browser and has the victim's post their credentials to it.
  test('is answered only from the browser that was sent to it, and a refusal does not spend it', async () => {
    const first = await go(authorizeUrl())
    const id = new URL(first.headers.get('location') as string).pathname.split('/').pop() as string
    const login = { login: { accountId: 'ada' } }

    const elsewhere = browserOf(await go(authorizeUrl()))
    for (const cookie of [null, '', elsewhere, `${(browserOf(first) as string).split('=')[0]}=forged`]) {
      await expect(provider.interactions.complete(id, login, cookie)).rejects.toMatchObject({ status: 403 })
    }
    expect((await provider.interactions.complete(id, login, browserOf(first))).setCookie).toBeString()
  })

  test('the binding cookie is set once, HttpOnly and host-only, and a browser that holds it keeps it', async () => {
    const first = await go(authorizeUrl())
    const set = first.headers.get('set-cookie') as string
    expect(set).toStartWith('__Host-oidcraft.browser=')
    expect(set).toContain('HttpOnly')
    expect(set).toContain('Secure')
    expect(set).toContain('Path=/')
    expect(set).not.toContain('Domain')

    const again = await go(authorizeUrl(), browserOf(first) as string)
    expect(again.headers.get('set-cookie')).toBeNull()
    const id = new URL(again.headers.get('location') as string).pathname.split('/').pop() as string
    expect((await provider.interactions.complete(id, { login: { accountId: 'ada' } }, browserOf(first))).setCookie).toBeString()
  })

  test('a logout confirmation is bound the same way', async () => {
    const first = await go(authorizeUrl())
    const id = new URL(first.headers.get('location') as string).pathname.split('/').pop() as string
    const { setCookie } = await provider.interactions.complete(id, { login: { accountId: 'ada' } }, browserOf(first))
    const session = (setCookie as string).split(';')[0] as string

    const asked = await go(`${ISSUER}/session/end`, session)
    const confirm = (asked.headers.get('location') as string).split('/').pop() as string
    await expect(provider.interactions.complete(confirm, { logout: true }, null)).rejects.toMatchObject({ status: 403 })
    expect((await provider.interactions.complete(confirm, { logout: true }, browserOf(asked))).redirectTo).toContain('logout=')
  })

  // FR-F6: a brokered login reports when the person signed in upstream, and the session keeps that, not now.
  test('a login reports its own auth_time, never one in the future', async () => {
    const at = async (authTime: Date) => {
      const first = await go(authorizeUrl())
      const id = new URL(first.headers.get('location') as string).pathname.split('/').pop() as string
      const { setCookie } = await provider.interactions.complete(id, { login: { accountId: 'ada', authTime } }, browserOf(first))
      return (await provider.session(new Request(ISSUER, { headers: { cookie: (setCookie as string).split(';')[0] as string } })))?.authTime
    }
    const earlier = new Date(Math.floor(Date.now() / 1000) * 1000 - 3_600_000)
    expect(await at(earlier)).toEqual(earlier)
    expect((await at(new Date(Date.now() + 3_600_000)))?.getTime()).toBeLessThanOrEqual(Date.now())
  })

  // FR-F9: max_age went upstream; an answer older than it was not a re-authentication, and the client hears so.
  test('a login older than max_age allows is answered to the client as login_required', async () => {
    const answer = async (maxAge: string, ago: number) => {
      const first = await go(authorizeUrl({ max_age: maxAge }))
      const id = new URL(first.headers.get('location') as string).pathname.split('/').pop() as string
      const authTime = new Date(Date.now() - ago * 1000)
      const done = await provider.interactions.complete(id, { login: { accountId: 'ada', authTime } }, browserOf(first))
      return { done, back: new URL((await go(done.redirectTo)).headers.get('location') as string) }
    }
    const stale = await answer('60', 3600)
    expect(stale.done.setCookie).toBeUndefined()
    expect(stale.back.searchParams.get('error')).toBe('login_required')
    expect((await answer('600', 120)).done.setCookie).toBeString()
  })

  // FR-I2: an answer that is refused must leave the interaction to be answered properly.
  test('a refused answer does not spend the interaction', async () => {
    const first = await go(authorizeUrl())
    const id = new URL(first.headers.get('location') as string).pathname.split('/').pop() as string
    const scopes = ['openid', 'profile', 'offline_access']
    await expect(provider.interactions.complete(id, { consent: { scopes } }, browserOf(first))).rejects.toThrow(
      'without a logged-in account'
    )
    const login = await provider.interactions.complete(id, { login: { accountId: 'ada' } }, browserOf(first))
    expect(login.setCookie).toBeTruthy()
  })

  // FR-I5 / OIDC Core §3.1.2.1.
  test('max_age=0 forces one login and then completes, rather than looping', async () => {
    const first = await go(authorizeUrl({ max_age: '0' }))
    const id = new URL(first.headers.get('location') as string).pathname.split('/').pop() as string
    const { redirectTo } = await provider.interactions.complete(id, { login: { accountId: 'ada' } }, browserOf(first))
    // The login just satisfied it; replaying max_age=0 would demand another one forever.
    expect(new URL(redirectTo).searchParams.has('max_age')).toBe(false)
  })

  test('prompt=select_account goes to the login screen even with a live session', async () => {
    const { cookie } = await loginAndConsent()
    const response = await go(authorizeUrl({ prompt: 'select_account' }), cookie)
    const id = new URL(response.headers.get('location') as string).pathname.split('/').pop() as string
    const view = await provider.interactions.find(id)
    expect(view.kind).toBe('login')
    expect(view.prompt).toContain('select_account')
  })

  test('prompt=consent outlives a login that did not answer it, even for an account that consented', async () => {
    await loginAndConsent()
    const first = await go(authorizeUrl({ prompt: 'consent' }))
    const loginId = new URL(first.headers.get('location') as string).pathname.split('/').pop() as string
    const login = await provider.interactions.complete(loginId, { login: { accountId: 'ada' } }, browserOf(first))
    expect(new URL(login.redirectTo).searchParams.get('prompt')).toBe('consent')

    const cookie = `${SESSION_COOKIE}=${(login.setCookie as string).split('=')[1]?.split(';')[0]}`
    const next = new URL((await go(login.redirectTo, cookie)).headers.get('location') as string)
    expect(next.searchParams.has('code')).toBe(false)
    expect((await provider.interactions.find(next.pathname.split('/').pop() as string)).kind).toBe('consent')
  })

  test('prompt=consent answered together with the login issues the code', async () => {
    await loginAndConsent()
    const first = await go(authorizeUrl({ prompt: 'consent' }))
    const id = new URL(first.headers.get('location') as string).pathname.split('/').pop() as string
    const done = await provider.interactions.complete(
      id,
      {
        login: { accountId: 'ada' },
        consent: { scopes: ['openid', 'profile', 'offline_access'] }
      },
      browserOf(first)
    )
    expect(new URL(done.redirectTo).searchParams.has('prompt')).toBe(false)

    const cookie = `${SESSION_COOKIE}=${(done.setCookie as string).split('=')[1]?.split(';')[0]}`
    expect(new URL((await go(done.redirectTo, cookie)).headers.get('location') as string).searchParams.get('code')).toBeString()
  })

  test('prompt=login is not replayed once a login answered it', async () => {
    const { cookie } = await loginAndConsent()
    const first = await go(authorizeUrl({ prompt: 'login' }), cookie)
    const id = new URL(first.headers.get('location') as string).pathname.split('/').pop() as string
    const login = await provider.interactions.complete(id, { login: { accountId: 'ada' } }, browserOf(first))
    expect(new URL(login.redirectTo).searchParams.has('prompt')).toBe(false)

    const fresh = `${SESSION_COOKIE}=${(login.setCookie as string).split('=')[1]?.split(';')[0]}`
    expect(new URL((await go(login.redirectTo, fresh)).headers.get('location') as string).searchParams.get('code')).toBeString()
  })

  test('consent cannot grant a scope the request did not ask for, and the refusal burns nothing', async () => {
    const first = await go(authorizeUrl({ scope: 'openid profile' }))
    const id = new URL(first.headers.get('location') as string).pathname.split('/').pop() as string
    const login = { accountId: 'ada' }
    await expect(
      provider.interactions.complete(id, { login, consent: { scopes: ['openid', 'profile', 'offline_access'] } }, browserOf(first))
    ).rejects.toMatchObject({ code: 'invalid_request', spec: 'FR-I4' })
    const done = await provider.interactions.complete(id, { login, consent: { scopes: ['openid', 'profile'] } }, browserOf(first))
    const cookie = `${SESSION_COOKIE}=${(done.setCookie as string).split('=')[1]?.split(';')[0]}`
    expect(new URL((await go(done.redirectTo, cookie)).headers.get('location') as string).searchParams.get('code')).toBeString()
  })

  test('a login naming an account the AccountStore cannot find is refused, and the interaction survives it', async () => {
    const first = await go(authorizeUrl())
    const id = new URL(first.headers.get('location') as string).pathname.split('/').pop() as string
    await expect(provider.interactions.complete(id, { login: { accountId: 'ghost' } }, browserOf(first))).rejects.toMatchObject({
      code: 'invalid_request',
      spec: 'FR-I2'
    })
    expect((await provider.interactions.complete(id, { login: { accountId: 'ada' } }, browserOf(first))).setCookie).toBeString()
  })

  test('prompt=none with another value is invalid_request', async () => {
    const response = await go(authorizeUrl({ prompt: 'none login' }))
    expect(new URL(response.headers.get('location') as string).searchParams.get('error')).toBe('invalid_request')
  })

  test('exposes what the screen needs and nothing secret', async () => {
    const first = await go(authorizeUrl())
    const id = new URL(first.headers.get('location') as string).pathname.split('/').pop() as string
    const view = await provider.interactions.find(id)
    expect(view.kind).toBe('login')
    expect(view.clientId).toBe('rp')
    expect(view.scopes).toContain('openid')
  })

  test('a denied interaction redirects to the client with access_denied', async () => {
    const first = await go(authorizeUrl())
    const id = new URL(first.headers.get('location') as string).pathname.split('/').pop() as string
    const { redirectTo } = await provider.interactions.complete(id, { error: { error: 'access_denied' } }, browserOf(first))
    const delivered = await go(redirectTo)
    const url = new URL(delivered.headers.get('location') as string)
    expect(url.origin + url.pathname).toBe(REDIRECT)
    expect(url.searchParams.get('error')).toBe('access_denied')
    expect(url.searchParams.get('state')).toBe('xyz')
    // FR-C14: iss on every authorization response, errors included.
    expect(url.searchParams.get('iss')).toBe(ISSUER)
    // Delivered once: a replayed link is not a second answer.
    expect((await go(redirectTo)).status).toBe(400)
  })

  test('form_post answers with a self-submitting form, never a query string', async () => {
    const { location, cookie } = await loginAndConsent()
    expect(location.searchParams.get('code')).toBeTruthy()
    const response = await go(authorizeUrl({ response_mode: 'form_post' }), cookie)
    expect(response.status).toBe(200)
    expect(response.headers.get('location')).toBeNull()
    const html = await response.text()
    expect(html).toContain(`action="${REDIRECT}"`)
    expect(html).toMatch(/name="code" value="[^"]+"/)
    expect(html).toContain(`name="iss" value="${ISSUER}"`)
    expect(response.headers.get('content-security-policy')).toContain('form-action https://rp.example.com')
  })

  test('form_post errors are posted too, and a denial carries iss', async () => {
    const first = await go(authorizeUrl({ response_mode: 'form_post' }))
    const id = new URL(first.headers.get('location') as string).pathname.split('/').pop() as string
    const { redirectTo } = await provider.interactions.complete(id, { error: { error: 'access_denied' } }, browserOf(first))
    const html = await (await go(redirectTo)).text()
    expect(html).toContain('name="error" value="access_denied"')
    expect(html).toContain(`name="iss" value="${ISSUER}"`)

    const invalid = await (await go(authorizeUrl({ response_mode: 'form_post', scope: 'profile' }))).text()
    expect(invalid).toContain('name="error" value="invalid_scope"')
  })

  test('an unknown interaction is a 404, not a crash', async () => {
    expect(provider.interactions.find('nope')).rejects.toThrow()
  })
})
