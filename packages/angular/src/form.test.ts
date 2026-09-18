import { beforeEach, describe, expect, it } from 'bun:test'
import { Injector, runInInjectionContext, signal } from '@angular/core'
import { oauthForm } from './form'
import { type NgxOAuth, OAUTH } from './oauth'

const installStorage = () => {
  const m = new Map<string, string>()
  Object.defineProperty(globalThis, 'localStorage', {
    value: {
      getItem: (k: string) => (m.has(k) ? (m.get(k) as string) : null),
      setItem: (k: string, v: string) => void m.set(k, String(v)),
      removeItem: (k: string) => void m.delete(k),
      clear: () => m.clear(),
      key: () => null,
      length: 0
    } as unknown as Storage,
    configurable: true,
    writable: true
  })
}
installStorage()

/**
 * A stand-in for the instance, so these tests are about the form and nothing else.
 *
 * Its members are real signals, not plain functions: the form derives `error` with `computed`, which
 * memoises on the signals it read — a plain closure is invisible to it and the value would be cached
 * for the lifetime of the form.
 */
const stub = () => {
  const calls: Array<Record<string, unknown>> = []
  const authorized = signal(false)
  const description = signal<string | undefined>(undefined)
  const oauth = {
    login: async (parameters?: Record<string, unknown>) => {
      calls.push(parameters ?? {})
    },
    isAuthorized: authorized,
    errorDescription: description
  } as unknown as NgxOAuth
  return {
    oauth,
    calls,
    succeed: () => authorized.set(true),
    fail: (message: string) => {
      authorized.set(false)
      description.set(message)
    }
  }
}

const build = (instance: NgxOAuth, options?: Parameters<typeof oauthForm>[0]) =>
  runInInjectionContext(Injector.create({ providers: [{ provide: OAUTH, useValue: instance }] }), () => oauthForm(options))

describe('oauthForm', () => {
  let harness: ReturnType<typeof stub>

  beforeEach(() => {
    harness = stub()
  })

  it('reports codes rather than sentences, so the markup owns the wording', () => {
    const form = build(harness.oauth)

    expect(form.username.error()).toBe('required')
    form.username.set('ada')
    expect(form.username.error()).toBeUndefined()
  })

  it('flags a value past maxLength', () => {
    const form = build(harness.oauth, { maxLength: 4 })

    form.username.set('abcde')

    expect(form.username.error()).toBe('tooLong')
    expect(form.valid()).toBe(false)
  })

  // a pristine form should not shout about fields nobody has touched yet
  it('hides errors until a submit has been attempted', async () => {
    const form = build(harness.oauth)

    expect(form.username.showError()).toBe(false)
    await form.submit()
    expect(form.username.showError()).toBe(true)
  })

  it('does not attempt a login while invalid', async () => {
    const form = build(harness.oauth)

    await form.submit()

    expect(harness.calls).toHaveLength(0)
  })

  it('logs in with what was entered, and clears it once that worked', async () => {
    const form = build(harness.oauth)
    form.username.set('ada')
    form.password.set('secret')
    harness.succeed()

    await form.submit()

    expect(harness.calls[0]).toEqual({ username: 'ada', password: 'secret' })
    expect(form.username.value()).toBe('')
    expect(form.password.value()).toBe('')
  })

  // the password goes, the username stays: a rejection is usually a typo in one of the two, and
  // retyping the address every time is the wrong thing to make someone do
  it('keeps the username when the provider rejects the attempt', async () => {
    const form = build(harness.oauth)
    form.username.set('ada')
    form.password.set('wrong')
    harness.fail('bad credentials')

    await form.submit()

    expect(form.username.value()).toBe('ada')
    expect(form.password.value()).toBe('')
    expect(form.submitted()).toBe(false)
  })

  it('surfaces the flow error, lets it be dismissed, and shows a different one', async () => {
    const form = build(harness.oauth)
    harness.fail('bad credentials')

    expect(form.error()).toBe('bad credentials')
    form.dismissError()
    expect(form.error()).toBeUndefined()

    harness.fail('account locked')
    expect(form.error()).toBe('account locked')
  })

  it('toggles password visibility', () => {
    const form = build(harness.oauth)

    expect(form.passwordVisible()).toBe(false)
    form.togglePasswordVisible()
    expect(form.passwordVisible()).toBe(true)
  })

  it('seeds from the options, for a prefilled or a test form', () => {
    const form = build(harness.oauth, { username: 'ada', password: 'x' })

    expect(form.username.value()).toBe('ada')
    expect(form.valid()).toBe(true)
  })

  it('prevents the default on a submit event, so a real form does not navigate', async () => {
    const form = build(harness.oauth)
    let prevented = false

    await form.submit({ preventDefault: () => (prevented = true) })

    expect(prevented).toBe(true)
  })
})
