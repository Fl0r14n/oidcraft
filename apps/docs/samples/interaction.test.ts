import { describe, expect, test } from 'bun:test'
import { memoryAdapter } from '@oidcraft/adapter/memory'
import { createProvider, OAuthError } from '@oidcraft/provider'
import { createAccounts, generateSecretKey, hotp } from '@oidcraft/provider/accounts'
import { type InteractionResult, oauthFieldError } from '@oidcraft/provider/interaction'
import { bunPasswordHasher } from '@oidcraft/provider/runtimes/bun'

const ISSUER = 'https://auth.example.com'
const CALLBACK = 'https://app.example.com/callback'
const VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
const CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'

// #region setup
const storage = await memoryAdapter()

const accounts = createAccounts({
  adapter: storage,
  hasher: bunPasswordHasher,
  secretKey: generateSecretKey(),
  issuer: 'Example'
})

const provider = createProvider({
  issuer: 'https://auth.example.com',
  adapter: { ...storage, accounts: accounts.store },
  interactionUrl: 'https://auth.example.com/interaction'
})
// #endregion setup

await storage.clients.upsert?.({
  clientId: 'app',
  clientName: 'Example App',
  redirectUris: [CALLBACK],
  grantTypes: ['authorization_code', 'refresh_token'],
  responseTypes: ['code'],
  scopes: ['openid', 'profile', 'email'],
  tokenEndpointAuthMethod: 'none',
  createdAt: new Date(),
  updatedAt: new Date()
})

// #region see-other
const seeOther = (location: string, setCookie?: string) => {
  const headers = new Headers({ location, 'cache-control': 'no-store' })
  if (setCookie) headers.append('set-cookie', setCookie)
  return new Response(null, { status: 303, headers })
}
// #endregion see-other

// #region login
const pendingSecondFactor = new Map<string, string>()

const submitLogin = async (id: string, request: Request) => {
  const form = new URLSearchParams(await request.text())
  // The browser's cookie proves this is the browser the provider sent here, not a page posting to it (FR-I2).
  const cookie = request.headers.get('cookie')
  if (form.get('decision') === 'cancel') {
    const { redirectTo } = await provider.interactions.complete(
      id,
      { error: { error: 'access_denied', description: 'the user cancelled the sign-in' } },
      cookie
    )
    return seeOther(redirectTo)
  }

  const username = form.get('username') ?? ''
  const password = form.get('password') ?? ''
  const errors = { username: oauthFieldError(username), password: oauthFieldError(password) }
  if (errors.username || errors.password) return Response.json({ errors }, { status: 400 })

  const result = await accounts.authenticate(username, password)
  if (!result.ok) return Response.json({ reason: result.reason }, { status: result.reason === 'locked' ? 429 : 401 })

  if (result.secondFactor) {
    pendingSecondFactor.set(id, result.accountId)
    return seeOther(`/interaction/${id}/otp`)
  }

  const { redirectTo, setCookie } = await provider.interactions.complete(
    id,
    { login: { accountId: result.accountId, acr: 'pwd', amr: ['pwd'] } },
    cookie
  )
  return seeOther(redirectTo, setCookie)
}
// #endregion login

// #region second-factor
const submitCode = async (id: string, request: Request) => {
  const form = new URLSearchParams(await request.text())
  const accountId = pendingSecondFactor.get(id)
  if (!accountId) return new Response('Sign in with your password first.', { status: 400 })

  const result = await accounts.verifySecondFactor(accountId, form.get('code') ?? '')
  if (!result.ok) return Response.json({ reason: result.reason }, { status: result.reason === 'locked' ? 429 : 401 })

  pendingSecondFactor.delete(id)
  const amr = result.method === 'otp' ? ['pwd', 'otp', 'mfa'] : ['pwd', 'mfa']
  const { redirectTo, setCookie } = await provider.interactions.complete(
    id,
    { login: { accountId, acr: 'mfa', amr } },
    request.headers.get('cookie')
  )
  return seeOther(redirectTo, setCookie)
}
// #endregion second-factor

// #region consent
const submitConsent = async (id: string, request: Request) => {
  const form = new URLSearchParams(await request.text())
  const view = await provider.interactions.find(id)
  const outcome: InteractionResult =
    form.get('decision') === 'allow'
      ? { consent: { scopes: view.scopes, claims: view.claims, authorizationDetails: view.authorizationDetails } }
      : { error: { error: 'access_denied', description: 'the user declined' } }
  const { redirectTo, setCookie } = await provider.interactions.complete(id, outcome, request.headers.get('cookie'))
  return seeOther(redirectTo, setCookie)
}
// #endregion consent

// #region expired
const answer = async (id: string, request: Request, handler: typeof submitConsent) => {
  try {
    return await handler(id, request)
  } catch (error) {
    if (error instanceof OAuthError) return new Response('This sign-in expired. Start again from the application.', { status: 400 })
    throw error
  }
}
// #endregion expired

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
const fromBase32 = (text: string) => {
  const bits = [...text].map(char => BASE32.indexOf(char).toString(2).padStart(5, '0')).join('')
  return new Uint8Array((bits.match(/.{8}/g) ?? []).map(byte => Number.parseInt(byte, 2)))
}
const totpNow = (secret: string) => hotp(fromBase32(secret), Math.floor(Date.now() / 30_000))

const register = async (username: string) => {
  const created = await accounts.register({ username, password: 'correct horse battery', claims: { name: username } })
  if (!created.ok) throw new Error(`could not register ${username}`)
  return created.accountId
}

const authorizeUrl = (over: Record<string, string> = {}) =>
  `${ISSUER}/authorize?${new URLSearchParams({
    client_id: 'app',
    redirect_uri: CALLBACK,
    response_type: 'code',
    scope: 'openid profile',
    state: 'af0ifjsldkj',
    nonce: 'n-0S6_WzA2Mj',
    code_challenge: CHALLENGE,
    code_challenge_method: 'S256',
    ...over
  })}`

const browser = () => {
  const jar = new Map<string, string>()
  const header = () => [...jar].map(([name, value]) => `${name}=${value}`).join('; ')
  const keep = (response: Response) => {
    for (const set of response.headers.getSetCookie()) {
      const [pair = ''] = set.split(';')
      const [name = '', value = ''] = pair.split('=')
      if (/max-age=0/i.test(set)) jar.delete(name)
      else jar.set(name, value)
    }
  }
  return {
    get cookie() {
      return header()
    },
    /** A form post from this browser, carrying its cookies as the real one would. */
    post(values: Record<string, string>) {
      return new Request(`${ISSUER}/interaction`, { method: 'POST', headers: { cookie: header() }, body: new URLSearchParams(values) })
    },
    async follow(response: Response) {
      let current = response
      for (;;) {
        keep(current)
        const location = current.headers.get('location')
        if (!location) throw new Error(`no redirect: ${current.status}`)
        const next = new URL(location, ISSUER)
        if (next.origin !== new URL(ISSUER).origin || next.pathname.startsWith('/interaction/')) return next
        current = await provider.handle(new Request(next, { headers: { cookie: header() } }))
      }
    },
    open(url: string) {
      return this.follow(new Response(null, { status: 303, headers: { location: url } }))
    }
  }
}

const interactionId = (url: URL) => {
  expect(url.origin + url.pathname.replace(/\/[^/]+$/, '')).toBe(`${ISSUER}/interaction`)
  return url.pathname.split('/').pop() as string
}

const exchange = async (code: string) => {
  const response = await provider.handle(
    new Request(`${ISSUER}/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: CALLBACK,
        client_id: 'app',
        code_verifier: VERIFIER
      })
    })
  )
  expect(response.status).toBe(200)
  const tokens = (await response.json()) as { id_token: string }
  return JSON.parse(Buffer.from(tokens.id_token.split('.')[1] as string, 'base64url').toString()) as Record<string, unknown>
}

describe('the interaction contract', () => {
  test('authorize suspends into a login, then a consent, then returns a code', async () => {
    const accountId = await register('ada')
    const ada = browser()

    // #region suspend
    const response = await provider.handle(new Request(authorizeUrl({ login_hint: 'ada', ui_locales: 'fr en' })))
    expect(response.status).toBe(303)
    const location = new URL(response.headers.get('location') as string)
    expect(location.pathname).toStartWith('/interaction/')
    const id = location.pathname.split('/').pop() as string
    // #endregion suspend
    await ada.follow(response)

    // #region read
    const view = await provider.interactions.find(id)
    expect(view).toMatchObject({
      kind: 'login',
      clientId: 'app',
      scopes: ['openid', 'profile'],
      prompt: [],
      loginHint: 'ada',
      acrValues: undefined,
      maxAge: undefined,
      uiLocales: ['fr', 'en'],
      redirectUri: 'https://app.example.com/callback'
    })
    const client = await provider.config.adapter.clients.find(view.clientId)
    expect(client?.clientName).toBe('Example App')
    // #endregion read

    // #region resume
    const signedIn = await submitLogin(id, ada.post({ username: 'ada', password: 'correct horse battery' }))
    expect(signedIn.headers.get('set-cookie')).toContain('HttpOnly')
    const next = await ada.follow(signedIn)
    const consentId = interactionId(next)
    expect((await provider.interactions.find(consentId)).kind).toBe('consent')
    // #endregion resume

    const back = await ada.follow(await submitConsent(consentId, ada.post({ decision: 'allow' })))
    expect(back.origin + back.pathname).toBe(CALLBACK)
    expect(back.searchParams.get('state')).toBe('af0ifjsldkj')
    expect(back.searchParams.get('iss')).toBe(ISSUER)

    const claims = await exchange(back.searchParams.get('code') as string)
    expect(claims).toMatchObject({ sub: accountId, acr: 'pwd', amr: ['pwd'] })
  })

  test('the field rules reject an empty or overlong field before any lookup', async () => {
    const ada = browser()
    const id = interactionId(await ada.open(authorizeUrl()))
    const response = await submitLogin(id, ada.post({ username: '', password: 'x'.repeat(200) }))
    expect(response.status).toBe(400)
    expect(await response.json()).toEqual({ errors: { username: 'required', password: 'tooLong' } })
    expect((await submitLogin(id, ada.post({ username: 'nobody', password: 'wrong-password' }))).status).toBe(401)
    expect((await provider.interactions.find(id)).kind).toBe('login')
  })

  test('a second factor is asked before the interaction is completed', async () => {
    const accountId = await register('grace')
    const begun = await accounts.totp.begin(accountId)
    if (!begun?.ok) throw new Error('enrolment did not start')
    const confirmed = await accounts.totp.confirm(accountId, await totpNow(begun.secret))
    const recovery = confirmed?.recoveryCodes[0] as string

    const grace = browser()
    const id = interactionId(await grace.open(authorizeUrl()))
    const first = await submitLogin(id, grace.post({ username: 'grace', password: 'correct horse battery' }))
    expect(first.headers.get('location')).toBe(`/interaction/${id}/otp`)
    expect(first.headers.get('set-cookie')).toBeNull()
    expect((await submitCode(id, grace.post({ code: '000000' }))).status).toBe(401)

    const consentId = interactionId(await grace.follow(await submitCode(id, grace.post({ code: recovery }))))
    const back = await grace.follow(await submitConsent(consentId, grace.post({ decision: 'allow' })))
    expect(await exchange(back.searchParams.get('code') as string)).toMatchObject({ acr: 'mfa', amr: ['pwd', 'mfa'] })
  })

  test('cancelling or declining sends access_denied to the client', async () => {
    const accountId = await register('alan')
    const alan = browser()

    // #region cancel
    const id = interactionId(await alan.open(authorizeUrl()))
    const cancelled = await alan.follow(await submitLogin(id, alan.post({ decision: 'cancel' })))
    expect(cancelled.origin + cancelled.pathname).toBe('https://app.example.com/callback')
    expect(Object.fromEntries(cancelled.searchParams)).toEqual({
      error: 'access_denied',
      error_description: 'the user cancelled the sign-in',
      state: 'af0ifjsldkj',
      iss: 'https://auth.example.com'
    })
    // #endregion cancel

    const loginId = interactionId(await alan.open(authorizeUrl()))
    const consentId = interactionId(
      await alan.follow(await submitLogin(loginId, alan.post({ username: 'alan', password: 'correct horse battery' })))
    )
    const declined = await alan.follow(await submitConsent(consentId, alan.post({ decision: 'deny' })))
    expect(declined.searchParams.get('error')).toBe('access_denied')
    expect(declined.searchParams.get('code')).toBeNull()
    expect(await provider.config.adapter.grants.listForAccount(accountId)).toEqual([])
  })

  test('an interaction is answered once; a stale or replayed id is an OAuthError', async () => {
    const accountId = await register('edsger')
    const edsger = browser()
    const id = interactionId(await edsger.open(authorizeUrl()))
    await submitLogin(id, edsger.post({ username: 'edsger', password: 'correct horse battery' }))

    // #region replayed
    const again = provider.interactions.complete(id, { login: { accountId } }, edsger.cookie)
    await expect(again).rejects.toBeInstanceOf(OAuthError)
    await expect(again).rejects.toMatchObject({ code: 'invalid_request', status: 404 })
    await expect(provider.interactions.find(id)).rejects.toMatchObject({ status: 404 })
    // #endregion replayed

    const page = await answer(id, edsger.post({ decision: 'allow' }), submitConsent)
    expect(page.status).toBe(400)
  })

  test('an answer posted from another browser is refused, and the interaction is still there', async () => {
    await register('hedy')
    const hedy = browser()
    const id = interactionId(await hedy.open(authorizeUrl()))

    // #region other-browser
    const attacker = browser()
    const planted = submitLogin(id, attacker.post({ username: 'hedy', password: 'correct horse battery' }))
    await expect(planted).rejects.toMatchObject({ code: 'invalid_request', status: 403, spec: 'FR-I2' })
    // #endregion other-browser

    const signedIn = await submitLogin(id, hedy.post({ username: 'hedy', password: 'correct horse battery' }))
    expect(signedIn.status).toBe(303)
  })

  test('consent is remembered as a grant, and revoking the grant asks again', async () => {
    const accountId = await register('barbara')
    const barbara = browser()
    const loginId = interactionId(await barbara.open(authorizeUrl()))
    const consentId = interactionId(
      await barbara.follow(await submitLogin(loginId, barbara.post({ username: 'barbara', password: 'correct horse battery' })))
    )
    await barbara.follow(await submitConsent(consentId, barbara.post({ decision: 'allow' })))

    // #region remembered
    const again = await barbara.open(authorizeUrl())
    expect(again.searchParams.get('code')).toBeString()

    const wider = interactionId(await barbara.open(authorizeUrl({ scope: 'openid profile email' })))
    expect(await provider.interactions.find(wider)).toMatchObject({ kind: 'consent', scopes: ['openid', 'profile', 'email'] })

    const [grant] = await provider.management.grants.listForAccount(accountId)
    expect(grant).toMatchObject({ clientId: 'app', scopes: ['openid', 'profile'] })
    await provider.management.grants.revoke(grant?.id as string)
    const asked = interactionId(await barbara.open(authorizeUrl()))
    expect((await provider.interactions.find(asked)).kind).toBe('consent')
    // #endregion remembered
  })

  test('consenting to fewer scopes than requested is refused, and nothing is stored', async () => {
    const accountId = await register('donald')
    const donald = browser()
    const loginId = interactionId(await donald.open(authorizeUrl({ scope: 'openid profile email' })))
    const consentId = interactionId(
      await donald.follow(await submitLogin(loginId, donald.post({ username: 'donald', password: 'correct horse battery' })))
    )

    // #region partial
    await expect(
      provider.interactions.complete(consentId, { consent: { scopes: ['openid', 'profile'] } }, donald.cookie)
    ).rejects.toMatchObject({
      code: 'invalid_request',
      spec: 'FR-I4'
    })
    const { redirectTo } = await provider.interactions.complete(
      consentId,
      { consent: { scopes: ['openid', 'profile', 'email'] } },
      donald.cookie
    )
    // #endregion partial

    expect(new URL(redirectTo).pathname).toBe('/authorize')
    expect((await provider.management.grants.listForAccount(accountId))[0]?.scopes).toEqual(['openid', 'profile', 'email'])
  })

  test('prompt=none never suspends', async () => {
    await register('frances')
    const frances = browser()

    // #region prompt-none
    const anonymous = await frances.open(authorizeUrl({ prompt: 'none' }))
    expect(anonymous.searchParams.get('error')).toBe('login_required')

    const loginId = interactionId(await frances.open(authorizeUrl()))
    await frances.follow(await submitLogin(loginId, frances.post({ username: 'frances', password: 'correct horse battery' })))
    const noGrant = await frances.open(authorizeUrl({ prompt: 'none' }))
    expect(noGrant.searchParams.get('error')).toBe('consent_required')
    // #endregion prompt-none
  })

  test('prompt=login, select_account, max_age and acr_values force a login over a live session', async () => {
    const accountId = await register('john')
    const john = browser()
    const loginId = interactionId(await john.open(authorizeUrl()))
    const consentId = interactionId(
      await john.follow(await submitLogin(loginId, john.post({ username: 'john', password: 'correct horse battery' })))
    )
    await john.follow(await submitConsent(consentId, john.post({ decision: 'allow' })))

    // #region reauthenticate
    for (const over of [{ prompt: 'login' }, { prompt: 'select_account' }, { max_age: '0' }, { acr_values: 'mfa' }]) {
      const id = interactionId(await john.open(authorizeUrl(over)))
      expect((await provider.interactions.find(id)).kind).toBe('login')
    }

    const stepUp = await provider.interactions.find(interactionId(await john.open(authorizeUrl({ acr_values: 'mfa' }))))
    expect(stepUp).toMatchObject({ kind: 'login', acrValues: ['mfa'], prompt: [] })
    // #endregion reauthenticate

    // #region acr-trusted
    const done = await provider.interactions.complete(stepUp.id, { login: { accountId, acr: 'pwd', amr: ['pwd'] } }, john.cookie)
    const back = await john.follow(seeOther(done.redirectTo, done.setCookie))
    expect(back.searchParams.get('code')).toBeString()
    expect(await exchange(back.searchParams.get('code') as string)).toMatchObject({ acr: 'pwd' })
    // #endregion acr-trusted
  })

  test('prompt=consent is asked even of an account that already consented', async () => {
    const accountId = await register('margaret')
    const first = browser()
    const loginId = interactionId(await first.open(authorizeUrl()))
    const consentId = interactionId(
      await first.follow(await submitLogin(loginId, first.post({ username: 'margaret', password: 'correct horse battery' })))
    )
    await first.follow(await submitConsent(consentId, first.post({ decision: 'allow' })))

    const other = browser()
    const loginFirst = interactionId(await other.open(authorizeUrl({ prompt: 'consent' })))
    const afterLoginOnly = await other.follow(
      await submitLogin(loginFirst, other.post({ username: 'margaret', password: 'correct horse battery' }))
    )
    expect(afterLoginOnly.searchParams.get('code')).toBeNull()
    expect((await provider.interactions.find(interactionId(afterLoginOnly))).kind).toBe('consent')

    const fresh = browser()
    // #region prompt-consent
    const id = interactionId(await fresh.open(authorizeUrl({ prompt: 'consent' })))
    const view = await provider.interactions.find(id)
    expect(view).toMatchObject({ kind: 'login', prompt: ['consent'] })

    const done = await provider.interactions.complete(
      id,
      {
        login: { accountId, acr: 'pwd', amr: ['pwd'] },
        ...(view.prompt.includes('consent') && { consent: { scopes: view.scopes } })
      },
      fresh.cookie
    )
    // #endregion prompt-consent
    expect((await fresh.follow(seeOther(done.redirectTo, done.setCookie))).searchParams.get('code')).toBeString()
  })

  test('a logout that cannot prove its sender is confirmed through an interaction', async () => {
    await register('ken')
    const ken = browser()
    const loginId = interactionId(await ken.open(authorizeUrl()))
    await ken.follow(await submitLogin(loginId, ken.post({ username: 'ken', password: 'correct horse battery' })))

    // #region logout
    const confirm = interactionId(await ken.open(`${ISSUER}/session/end`))
    expect((await provider.interactions.find(confirm)).kind).toBe('logout')

    const { redirectTo } = await provider.interactions.complete(confirm, { logout: true }, ken.cookie)
    const ended = await provider.handle(new Request(redirectTo, { headers: { cookie: ken.cookie } }))
    expect(ended.status).toBe(200)
    expect(ended.headers.get('set-cookie')).toContain('Max-Age=0')
    // #endregion logout
  })
})
