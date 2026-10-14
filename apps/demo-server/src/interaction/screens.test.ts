import { describe, expect, test } from 'bun:test'
import type { InteractionRequest } from 'oidcraft/interaction'
import { consentScreen, deviceConfirmScreen, errorScreen, loginScreen, selectAccountScreen } from './screens'

const view = { id: 'i1', kind: 'login', clientId: '<script>', scopes: ['openid', 'email'], prompt: [] } as unknown as InteractionRequest

const firstButton = (html: string) => html.match(/<button[^>]*>/)?.[0] ?? ''

/** What `conformance/plan.json` drives these screens by. Renaming any of it breaks the CI gate (NFR-C1). */
describe('the conformance browser contract', () => {
  test('login has fields u and p, and its first submit button signs in', async () => {
    const html = await (await loginScreen(view, undefined, [{ id: 'google', label: 'Google' }])).text()
    expect(html).toContain('id="u"')
    expect(html).toContain('id="p"')
    expect(html).toContain('Sign in')
    expect(firstButton(html)).toContain('type="submit"')
    expect(firstButton(html)).not.toContain('name="provider"')
    expect(html).not.toContain('<script>')
  })

  test('account selection says so and submits on the first button', async () => {
    const html = await (await selectAccountScreen(view, [{ accountId: 'ada', label: 'ada' }])).text()
    expect(html).toContain('Choose an account')
    expect(firstButton(html)).toContain('type="submit"')
  })

  test('consent has an allow button', async () => {
    expect(await (await consentScreen(view)).text()).toMatch(/<button[^>]*value="allow"/)
  })

  test('the error page says the sign-in cannot continue', async () => {
    const response = await errorScreen('invalid_request', 'bad redirect_uri')
    expect(response.status).toBe(400)
    expect(await response.text()).toContain('cannot continue')
  })
})

test('the device confirmation carries the code it is answering', async () => {
  expect(await (await deviceConfirmScreen('ABCD-EFGH', 'TV', ['openid'])).text()).toMatch(
    /type="hidden" name="user_code" value="ABCD-EFGH"/
  )
})

test('a rejected login keeps what was typed and says what is wrong', async () => {
  const html = await (await loginScreen(view, { username: 'ada', errors: { username: undefined, password: 'required' } }, [], 400)).text()
  expect(html).toContain('value="ada"')
  expect(html).toContain('Enter your password')
  expect(html).toContain('aria-invalid="true"')
})
