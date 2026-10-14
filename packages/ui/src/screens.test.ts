import { describe, expect, test } from 'bun:test'
import type { InteractionRequest } from 'oidcraft/interaction'
import { createScreens } from './screens'

const screens = createScreens({ brand: { name: 'Acme', host: 'id.acme.test' } })

const view = { id: 'i1', kind: 'login', clientId: '<script>', scopes: ['openid', 'email'], prompt: [] } as unknown as InteractionRequest

const firstButton = (html: string) => html.match(/<button[^>]*>/)?.[0] ?? ''

/** What `conformance/plan.json` drives these screens by. Renaming any of it breaks the CI gate (NFR-C1). */
describe('the conformance browser contract', () => {
  test('login has fields u and p, and its first submit button signs in', async () => {
    const html = await (await screens.login(view, undefined, [{ id: 'google', label: 'Google' }])).text()
    expect(html).toContain('id="u"')
    expect(html).toContain('id="p"')
    expect(html).toContain('Sign in')
    expect(firstButton(html)).toContain('type="submit"')
    expect(firstButton(html)).not.toContain('name="provider"')
    expect(html).not.toContain('<script>')
  })

  test('account selection says so and submits on the first button', async () => {
    const html = await (await screens.selectAccount(view, [{ accountId: 'ada', label: 'ada' }])).text()
    expect(html).toContain('Choose an account')
    expect(firstButton(html)).toContain('type="submit"')
  })

  test('consent has an allow button', async () => {
    expect(await (await screens.consent(view)).text()).toMatch(/<button[^>]*value="allow"/)
  })

  test('the error page says the sign-in cannot continue', async () => {
    const response = await screens.error('invalid_request', 'bad redirect_uri')
    expect(response.status).toBe(400)
    expect(await response.text()).toContain('cannot continue')
  })
})

test('the device confirmation carries the code it is answering', async () => {
  expect(await (await screens.deviceConfirm('ABCD-EFGH', 'TV', ['openid'])).text()).toMatch(
    /type="hidden" name="user_code" value="ABCD-EFGH"/
  )
})

test('a rejected login keeps what was typed and says what is wrong', async () => {
  const html = await (await screens.login(view, { username: 'ada', errors: { username: undefined, password: 'required' } }, [], 400)).text()
  expect(html).toContain('value="ada"')
  expect(html).toContain('Enter your password')
  expect(html).toContain('aria-invalid="true"')
})

test('a theme value that could close the style element is dropped, not escaped', async () => {
  const themed = createScreens({ brand: { name: 'Acme', host: 'id.acme.test' }, theme: { accent: '#0a7', radius: '1px}</style><script>' } })
  const html = await (await themed.error('invalid_request', undefined)).text()
  expect(html).toContain('--oc-accent:#0a7')
  expect(html).not.toContain('<script>')
})

test('every form posts where it is told to', async () => {
  const prefixed = createScreens({
    brand: { name: 'Acme', host: 'id.acme.test' },
    urls: { interaction: (id, action) => `/t/acme/i/${id}/${action}` }
  })
  expect(await (await prefixed.login(view)).text()).toContain('action="/t/acme/i/i1/login"')
})
