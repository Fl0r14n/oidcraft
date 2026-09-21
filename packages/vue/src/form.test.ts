import { beforeEach, describe, expect, it } from 'bun:test'
import { createApp, effectScope } from 'vue'
import { useOAuthForm } from './form'
import { createOAuth, type OAuth } from './module'

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

const config = { issuerPath: 'https://idp', clientId: 'c', tokenPath: 'https://idp/token' }

/**
 * `useOAuthForm` resolves its instance through injection and subscribes, so it needs both a running
 * app context and an effect scope — which is what a component setup is.
 */
const inSetup = <T>(oauth: OAuth, fn: () => T): T => {
  const app = createApp({ render: () => null })
  app.use(oauth)
  const scope = effectScope(true)
  return app.runWithContext(() => scope.run(fn) as T)
}

describe('useOAuthForm', () => {
  let oauth: OAuth
  let attempts: Array<Record<string, unknown>>

  beforeEach(() => {
    attempts = []
    oauth = createOAuth({
      config,
      functions: {
        refresh: async token => token,
        resourceOwnerLogin: async parameters => {
          attempts.push(parameters as unknown as Record<string, unknown>)
          return { error: 'invalid_grant', error_description: 'bad credentials' }
        }
      }
    })
  })

  it('reports codes rather than sentences, so the markup owns the wording', () => {
    const form = inSetup(oauth, () => useOAuthForm())

    expect(form.errors.value.username).toBe('required')
    form.username.value = 'ada'
    expect(form.errors.value.username).toBeUndefined()
  })

  // `v-model="username"` after destructuring is the point of the flat shape
  it('is writable through the ref a template would bind', () => {
    const form = inSetup(oauth, () => useOAuthForm())

    form.username.value = 'ada'

    expect(form.username.value).toBe('ada')
    expect(form.valid.value).toBe(false) // password still empty
    form.password.value = 'secret'
    expect(form.valid.value).toBe(true)
  })

  it('hides errors until a submit has been attempted', async () => {
    const form = inSetup(oauth, () => useOAuthForm())

    expect(form.showErrors.value.username).toBe(false)
    await form.submit()
    expect(form.showErrors.value.username).toBe(true)
  })

  it('does not attempt a login while invalid', async () => {
    const form = inSetup(oauth, () => useOAuthForm())

    await form.submit()

    expect(attempts).toHaveLength(0)
  })

  // the password goes, the username stays, and the flow error reaches the form
  it('keeps the username and surfaces the error when the provider rejects', async () => {
    const form = inSetup(oauth, () => useOAuthForm({ username: 'ada', password: 'wrong' }))

    await form.submit()

    expect(attempts[0]).toEqual({ username: 'ada', password: 'wrong' })
    expect(form.username.value).toBe('ada')
    expect(form.password.value).toBe('')
    expect(form.error.value).toBe('bad credentials')
  })

  it('lets the error be dismissed', async () => {
    const form = inSetup(oauth, () => useOAuthForm({ username: 'ada', password: 'wrong' }))
    await form.submit()

    form.dismissError()

    expect(form.error.value).toBeUndefined()
  })

  it('toggles password visibility', () => {
    const form = inSetup(oauth, () => useOAuthForm())

    expect(form.passwordVisible.value).toBe(false)
    form.togglePasswordVisible()
    expect(form.passwordVisible.value).toBe(true)
  })
})
