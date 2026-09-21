import { beforeEach, describe, expect, it } from 'bun:test'
import { createOAuthForm, type OAuthFormHost } from './form'

/** A stand-in for an instance: the controller needs three things from one, and this is all three. */
const host = () => {
  const calls: Array<{ username: string; password: string }> = []
  let authorized = false
  let description: string | undefined
  return {
    calls,
    oauth: {
      login: async parameters => {
        calls.push(parameters as { username: string; password: string })
      },
      isAuthorized: () => authorized,
      errorDescription: () => description
    } satisfies OAuthFormHost,
    succeed: () => {
      authorized = true
    },
    fail: (message: string) => {
      authorized = false
      description = message
    }
  }
}

describe('createOAuthForm', () => {
  let harness: ReturnType<typeof host>

  beforeEach(() => {
    harness = host()
  })

  it('does not attempt a login while invalid', async () => {
    const form = createOAuthForm(harness.oauth)

    await form.submit()

    expect(harness.calls).toHaveLength(0)
    expect(form.view().submitted).toBe(true)
  })

  it('logs in with what was entered, and clears it once that worked', async () => {
    const form = createOAuthForm(harness.oauth)
    form.setUsername('ada')
    form.setPassword('secret')
    harness.succeed()

    await form.submit()

    expect(harness.calls[0]).toEqual({ username: 'ada', password: 'secret' })
    expect(form.view().username.value).toBe('')
    expect(form.view().password.value).toBe('')
  })

  it('keeps the username when the provider rejects the attempt', async () => {
    const form = createOAuthForm(harness.oauth)
    form.setUsername('ada')
    form.setPassword('wrong')
    harness.fail('bad credentials')

    await form.submit()

    expect(form.view().username.value).toBe('ada')
    expect(form.view().password.value).toBe('')
    expect(form.view().submitted).toBe(false)
  })

  it('clears submitting even when login throws', async () => {
    const form = createOAuthForm({
      ...harness.oauth,
      login: async () => {
        throw new Error('network')
      }
    })
    form.setUsername('ada')
    form.setPassword('secret')

    await form.submit().catch(() => undefined)

    expect(form.view().submitting).toBe(false)
  })

  it('dismisses the error that is showing, not a later one', () => {
    const form = createOAuthForm(harness.oauth)
    harness.fail('bad credentials')

    form.dismissError()
    expect(form.view().error).toBeUndefined()

    harness.fail('account locked')
    expect(form.view().error).toBe('account locked')
  })

  it('toggles password visibility', () => {
    const form = createOAuthForm(harness.oauth)

    expect(form.view().passwordVisible).toBe(false)
    form.togglePasswordVisible()
    expect(form.view().passwordVisible).toBe(true)
  })

  it('seeds from the options, for a prefilled or a test form', () => {
    const form = createOAuthForm(harness.oauth, { username: 'ada', password: 'x' })

    expect(form.view().username.value).toBe('ada')
    expect(form.view().valid).toBe(true)
  })

  it('prevents the default, so a real form does not navigate', async () => {
    const form = createOAuthForm(harness.oauth)
    let prevented = false

    await form.submit({ preventDefault: () => (prevented = true) })

    expect(prevented).toBe(true)
  })

  // the store is what every binding subscribes to; a write that does not notify is a view that
  // never updates
  it('notifies subscribers on every write', () => {
    const form = createOAuthForm(harness.oauth)
    let notified = 0
    form.store.subscribe(() => {
      notified++
    })

    form.setUsername('ada')
    form.setPassword('x')
    form.togglePasswordVisible()

    expect(notified).toBe(3)
  })
})
