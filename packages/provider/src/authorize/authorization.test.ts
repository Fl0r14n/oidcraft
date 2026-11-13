import { describe, expect, test } from 'bun:test'
import type { Client } from '../index'
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
  loginAndConsent,
  post,
  provider,
  REDIRECT,
  useFlow,
  verifier
} from '../test-flow'
import { detailsConsentId } from './authorization'

useFlow()

describe('authorization endpoint', () => {
  test('an unknown client is reported directly, never redirected', async () => {
    const response = await go(authorizeUrl({ client_id: 'ghost' }))
    expect(response.status).toBe(400)
    expect((await response.json()).error).toBe('invalid_request')
  })

  // NFR-S2 / RFC 9700 §4.1: redirecting to an unregistered URI is an open redirector.
  test('an unregistered redirect_uri is reported directly, never redirected', async () => {
    const response = await go(authorizeUrl({ redirect_uri: 'https://evil.example.net/cb' }))
    expect(response.status).toBe(400)
    expect(response.headers.get('location')).toBeNull()
    expect((await response.json()).error_description).toContain('not registered')
  })

  test('an exact-match redirect_uri is required, not a prefix', async () => {
    const response = await go(authorizeUrl({ redirect_uri: `${REDIRECT}/deeper` }))
    expect(response.status).toBe(400)
  })

  // FR-C3: required unless the host opted the client out, which this one is not — the nonce alone is not enough.
  test('a missing code_challenge is refused', async () => {
    const url = new URL(authorizeUrl())
    url.searchParams.delete('code_challenge')
    const response = await go(url.toString())
    expect(new URL(response.headers.get('location') as string).searchParams.get('error')).toBe('invalid_request')
  })

  // RFC 8252 §7.3: a native app picks its loopback port from the OS at request time.
  describe('loopback redirect URIs', () => {
    const native = (redirectUri: string) =>
      adapter.clients.upsert?.(client({ clientId: 'cli', tokenEndpointAuthMethod: 'none', redirectUris: [redirectUri] }))
    const status = async (redirectUri: string) => (await go(authorizeUrl({ client_id: 'cli', redirect_uri: redirectUri }))).status

    test('any port is accepted on a loopback IP literal', async () => {
      await native('http://127.0.0.1/cb')
      expect(await status('http://127.0.0.1:51234/cb')).toBe(303)
      await adapter.clients.upsert?.({ ...((await adapter.clients.find('cli')) as Client), redirectUris: ['http://[::1]/cb'] })
      expect(await status('http://[::1]:8123/cb')).toBe(303)
    })

    test('only the port may differ', async () => {
      await native('http://127.0.0.1/cb')
      expect(await status('http://127.0.0.1:51234/other')).toBe(400)
      expect(await status('http://127.0.0.1:51234/cb?extra=1')).toBe(400)
      expect(await status('https://127.0.0.1:51234/cb')).toBe(400)
    })

    test('the hostname localhost gets no exception', async () => {
      await native('http://localhost/cb')
      expect(await status('http://localhost:51234/cb')).toBe(400)
    })
  })

  test('code_challenge_method=plain is refused', async () => {
    const response = await go(authorizeUrl({ code_challenge_method: 'plain' }))
    const error = new URL(response.headers.get('location') as string).searchParams
    expect(error.get('error')).toBe('invalid_request')
    expect(error.get('error_description')).toContain('S256')
  })

  test('an unsupported response_type redirects with the error and the state', async () => {
    const response = await go(authorizeUrl({ response_type: 'token' }))
    const params = new URL(response.headers.get('location') as string).searchParams
    expect(params.get('error')).toBe('unsupported_response_type')
    expect(params.get('state')).toBe('xyz')
  })

  test('a scope without openid is refused', async () => {
    const response = await go(authorizeUrl({ scope: 'profile' }))
    expect(new URL(response.headers.get('location') as string).searchParams.get('error')).toBe('invalid_scope')
  })

  test('with no session it suspends into a login interaction', async () => {
    const response = await go(authorizeUrl())
    expect(response.status).toBe(303)
    expect(response.headers.get('location')).toContain(`${ISSUER}/interaction/`)
  })

  // OIDC Core §3.1.2.6
  test('prompt=none with no session is login_required, not an interaction', async () => {
    const response = await go(authorizeUrl({ prompt: 'none' }))
    const params = new URL(response.headers.get('location') as string).searchParams
    expect(params.get('error')).toBe('login_required')
    expect(params.get('iss')).toBe(ISSUER)
  })

  test('prompt=none with a session but no grant is consent_required', async () => {
    const first = await go(authorizeUrl())
    const id = new URL(first.headers.get('location') as string).pathname.split('/').pop() as string
    const login = await provider.interactions.complete(id, { login: { accountId: 'ada' } }, browserOf(first))
    const cookie = `${SESSION_COOKIE}=${(login.setCookie as string).split('=')[1]?.split(';')[0]}`
    const response = await go(authorizeUrl({ prompt: 'none' }), cookie)
    expect(new URL(response.headers.get('location') as string).searchParams.get('error')).toBe('consent_required')
  })

  test('a completed login and consent yields a code, the state and the issuer', async () => {
    const { location } = await loginAndConsent()
    expect(location.origin + location.pathname).toBe(REDIRECT)
    expect(location.searchParams.get('code')).toBeTruthy()
    expect(location.searchParams.get('state')).toBe('xyz')
    // FR-C14
    expect(location.searchParams.get('iss')).toBe(ISSUER)
  })

  // FR-I4: the second visit is silent.
  // OIDC Core §3.1.2.1: acr_values is a request. After one login, what it achieved is the answer.
  test('an acr the login cannot meet is asked for once, not forever', async () => {
    const { location } = await loginAndConsent({ acr_values: 'mfa' })
    expect(location.searchParams.get('code')).toBeTruthy()
  })

  // FR-I4: one grant per account and client, however the first consents arrive.
  test('a first consent from two tabs at once makes one grant, and both tabs get a working code', async () => {
    const first = await go(authorizeUrl())
    const loginId = new URL(first.headers.get('location') as string).pathname.split('/').pop() as string
    const login = await provider.interactions.complete(loginId, { login: { accountId: 'ada' } }, browserOf(first))
    const cookie = `${SESSION_COOKIE}=${(login.setCookie as string).split('=')[1]?.split(';')[0]}`

    const tabs = await Promise.all([go(login.redirectTo, cookie), go(authorizeUrl(), cookie)])
    const consentIds = tabs.map(tab => new URL(tab.headers.get('location') as string).pathname.split('/').pop() as string)
    const consents = await Promise.all(
      consentIds.map((id, tab) =>
        provider.interactions.complete(
          id,
          { consent: { scopes: ['openid', 'profile', 'offline_access'] } },
          browserOf(tabs[tab] as Response)
        )
      )
    )

    expect(await adapter.grants.listForAccount('ada')).toHaveLength(1)
    for (const consent of consents) {
      const code = new URL((await go(consent.redirectTo, cookie)).headers.get('location') as string).searchParams.get('code')
      const redeemed = await post(
        '/token',
        { grant_type: 'authorization_code', code: code as string, redirect_uri: REDIRECT, code_verifier: verifier },
        { authorization: basic() }
      )
      expect(redeemed.status).toBe(200)
    }
  })

  test('a remembered grant skips consent on the next authorization', async () => {
    const { cookie } = await loginAndConsent()
    const again = await go(authorizeUrl(), cookie)
    const location = new URL(again.headers.get('location') as string)
    expect(location.searchParams.get('code')).toBeTruthy()
  })
})

describe('a derived identifier has one input it can come from', () => {
  test('a newline moving between the account and the client changes the details-consent id', async () => {
    const details = [{ type: 'payment' }]
    expect(await detailsConsentId('a\nb', 'c', details)).not.toBe(await detailsConsentId('a', 'b\nc', details))
  })
})

// FR-C23, OIDC DCR 1.0 §2: a client's default_acr_values, voluntary as acr_values are.
describe('default acr values', () => {
  /** Authorize and answer each interaction with a login at `acr`, or consent; the views seen and where it ends. */
  const run = async (params: Record<string, string>, acr: string, cookie = '') => {
    const views: { kind: string; acrValues: string[] | undefined }[] = []
    let response = await go(authorizeUrl(params), cookie)
    for (let leg = 0; leg < 4; leg++) {
      const location = new URL(response.headers.get('location') as string)
      if (!location.pathname.startsWith('/interaction/')) return { location, views, cookie }
      const id = location.pathname.split('/').pop() as string
      const view = await provider.interactions.find(id)
      views.push(view)
      const answer =
        view.kind === 'login' ? { login: { accountId: 'ada', acr } } : { consent: { scopes: view.scopes, claims: view.claims } }
      const done = await provider.interactions.complete(id, answer, browserOf(response))
      if (done.setCookie) cookie = `${SESSION_COOKIE}=${done.setCookie.split('=')[1]?.split(';')[0]}`
      response = await go(done.redirectTo, cookie)
    }
    throw new Error('never reached the client')
  }
  const logins = (views: { kind: string }[]) => views.filter(view => view.kind === 'login').length

  test('a session below them signs in once more, and the code is issued whatever that login reached', async () => {
    const first = await run({}, 'pwd')
    await adapter.clients.upsert?.(client({ defaultAcrValues: ['mfa'] }))
    const again = await run({}, 'pwd', first.cookie)
    expect(logins(again.views)).toBe(1)
    expect(again.views[0]?.acrValues).toEqual(['mfa'])
    expect(again.location.searchParams.get('code')).toBeTruthy()
  })

  test('a session that meets them is not asked again', async () => {
    await adapter.clients.upsert?.(client({ defaultAcrValues: ['mfa'] }))
    const first = await run({}, 'mfa')
    const again = await run({}, 'mfa', first.cookie)
    expect(logins(again.views)).toBe(0)
    expect(again.location.searchParams.get('code')).toBeTruthy()
  })

  test('acr_values on the request, or an acr in claims, override them', async () => {
    const first = await run({}, 'pwd')
    await adapter.clients.upsert?.(client({ defaultAcrValues: ['mfa'] }))
    expect(logins((await run({ acr_values: 'pwd' }, 'pwd', first.cookie)).views)).toBe(0)
    const voluntary = JSON.stringify({ id_token: { acr: { values: ['pwd'] } } })
    expect(logins((await run({ claims: voluntary }, 'pwd', first.cookie)).views)).toBe(0)
  })

  test('are advertised only when the configuration lists them, and a client naming another is refused', async () => {
    const metadata = async () => (await provider.handle(new Request(`${ISSUER}/.well-known/openid-configuration`))).json()
    expect(await metadata()).not.toHaveProperty('acr_values_supported')
    drive(build({ acrValues: ['pwd', 'mfa'], upstreams: [{ id: 'google' }], features: { dynamicRegistration: true } }))
    expect((await metadata()).acr_values_supported).toEqual(['pwd', 'mfa', 'urn:oidcraft:idp:google'])

    const register = (values: string[]) =>
      provider.handle(
        new Request(`${ISSUER}/register`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ redirect_uris: [REDIRECT], token_endpoint_auth_method: 'none', default_acr_values: values })
        })
      )
    const accepted = await register(['mfa'])
    expect(accepted.status).toBe(201)
    expect((await accepted.json()).default_acr_values).toEqual(['mfa'])
    expect((await register(['urn:oidcraft:idp:google'])).status).toBe(201)
    const refused = await register(['gold'])
    expect(refused.status).toBe(400)
    expect((await refused.json()).error).toBe('invalid_client_metadata')
  })
})
