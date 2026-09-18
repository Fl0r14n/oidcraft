import { beforeEach, describe, expect, it } from 'bun:test'
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import { type OAuth, OAuthType } from 'react-oauth-oidc/core'
import { useOAuthForm } from './form'
import { OAuthProvider } from './provider'
import { createOAuth, flush, installStorage, mockOAuthFunctions, registerOAuthCleanup } from './test-utils'

const local = installStorage()
registerOAuthCleanup()

let oauth: OAuth
let functions: ReturnType<typeof mockOAuthFunctions>

beforeEach(() => {
  local.clear()
  functions = mockOAuthFunctions()
  oauth = createOAuth({ config: { tokenPath: '/t', clientId: 'c' }, functions })
})

/** No MUI anywhere — the point of the hook is that a skin is optional. */
const Form = ({ maxLength }: { maxLength?: number } = {}) => {
  const form = useOAuthForm({ maxLength })
  return (
    <form onSubmit={event => void form.submit(event)}>
      <input aria-label="username" value={form.username.value} onChange={e => form.username.onChange(e.target.value)} />
      <input aria-label="password" value={form.password.value} onChange={e => form.password.onChange(e.target.value)} />
      <button type="submit">go</button>
      <span data-testid="state">
        {[
          form.username.error ?? '-',
          form.password.error ?? '-',
          form.username.showError ? 'shown' : 'hidden',
          form.valid ? 'valid' : 'invalid',
          form.submitting ? 'submitting' : 'idle',
          form.error ?? '-',
          form.passwordVisible ? 'visible' : 'masked'
        ].join('|')}
      </span>
      <button type="button" data-testid="toggle" onClick={form.togglePasswordVisible}>
        eye
      </button>
      <button type="button" data-testid="dismiss" onClick={form.dismissError}>
        x
      </button>
    </form>
  )
}

const mount = (ui: React.ReactNode) => render(<OAuthProvider oauth={oauth}>{ui}</OAuthProvider>)
const state = () => screen.getByTestId('state').textContent!.split('|')
// fireEvent, not a raw dispatch: React tracks the input's value internally and ignores an event whose
// value it did not see being set
const type = (label: string, value: string) => fireEvent.change(screen.getByLabelText(label), { target: { value } })

describe('useOAuthForm', () => {
  it('reports error codes rather than sentences, so the skin owns the wording', () => {
    mount(<Form />)

    expect(state()[0]).toBe('required')
    expect(state()[1]).toBe('required')

    type('username', 'jane')
    expect(state()[0]).toBe('-')
    cleanup()
  })

  it('flags a value past maxLength', () => {
    mount(<Form maxLength={4} />)

    type('username', 'toolong')

    expect(state()[0]).toBe('tooLong')
    expect(state()[3]).toBe('invalid')
    cleanup()
  })

  it('hides errors until a submit has been attempted', () => {
    mount(<Form />)
    // pristine and empty: invalid, but not yet shouting about it
    expect(state()[2]).toBe('hidden')
    expect(state()[3]).toBe('invalid')

    act(() => screen.getByText('go').click())

    expect(state()[2]).toBe('shown')
    cleanup()
  })

  it('does not attempt a login while invalid', () => {
    mount(<Form />)

    act(() => screen.getByText('go').click())

    expect(functions.resourceOwnerLogin).not.toHaveBeenCalled()
    cleanup()
  })

  it('logs in with the entered credentials and clears them', async () => {
    functions.resourceOwnerLogin.mockResolvedValue({ access_token: 'ro', token_type: 'Bearer', type: OAuthType.RESOURCE })
    mount(<Form />)
    type('username', 'jane')
    type('password', 'secret')

    await act(async () => {
      screen.getByText('go').click()
      await flush()
    })

    expect(functions.resourceOwnerLogin).toHaveBeenCalledWith({ username: 'jane', password: 'secret' }, { tokenPath: '/t', clientId: 'c' })
    // a rejected password should not stay in the DOM either, so this happens regardless of the outcome
    expect((screen.getByLabelText('password') as HTMLInputElement).value).toBe('')
    expect(oauth.token().access_token).toBe('ro')
    cleanup()
  })

  it('keeps the username when the IdP rejects the attempt', async () => {
    functions.resourceOwnerLogin.mockResolvedValue({ error: 'invalid_grant', error_description: 'Bad credentials' })
    mount(<Form />)
    type('username', 'jane')
    type('password', 'wrong')

    await act(async () => {
      screen.getByText('go').click()
      await flush()
    })

    // mistyping a password should not cost the user their email as well
    expect((screen.getByLabelText('username') as HTMLInputElement).value).toBe('jane')
    expect((screen.getByLabelText('password') as HTMLInputElement).value).toBe('')
    // and the field just emptied must not shout "required" over the IdP's own message
    expect(state()[2]).toBe('hidden')
    expect(state()[5]).toBe('Bad credentials')
    cleanup()
  })

  it('clears the username too once the login succeeds', async () => {
    functions.resourceOwnerLogin.mockResolvedValue({ access_token: 'ro', token_type: 'Bearer', type: OAuthType.RESOURCE })
    mount(<Form />)
    type('username', 'jane')
    type('password', 'secret')

    await act(async () => {
      screen.getByText('go').click()
      await flush()
    })

    expect((screen.getByLabelText('username') as HTMLInputElement).value).toBe('')
    expect((screen.getByLabelText('password') as HTMLInputElement).value).toBe('')
    cleanup()
  })

  it('surfaces the flow error, lets it be dismissed, and re-shows a new one', async () => {
    mount(<Form />)
    expect(state()[5]).toBe('-')

    act(() => oauth.setToken({ error: 'invalid_grant', error_description: 'Bad credentials' }))
    expect(state()[5]).toBe('Bad credentials')

    act(() => screen.getByTestId('dismiss').click())
    expect(state()[5]).toBe('-')

    // a second, different failure must not stay suppressed by the earlier dismissal
    act(() => oauth.setToken({ error: 'invalid_grant', error_description: 'Still bad' }))
    expect(state()[5]).toBe('Still bad')
    cleanup()
  })

  it('re-shows a dismissed error when the next attempt fails identically', async () => {
    functions.resourceOwnerLogin.mockResolvedValue({ error: 'invalid_grant', error_description: 'Bad credentials' })
    mount(<Form />)
    type('username', 'jane')
    type('password', 'wrong')

    await act(async () => {
      screen.getByText('go').click()
      await flush()
    })
    expect(state()[5]).toBe('Bad credentials')

    act(() => screen.getByTestId('dismiss').click())
    expect(state()[5]).toBe('-')

    // same credentials, same rejection, same message — the user still has to be told. Keyed on a
    // boolean this stayed hidden; keyed on the message alone it also would have.
    type('username', 'jane')
    type('password', 'wrong')
    await act(async () => {
      screen.getByText('go').click()
      await flush()
    })

    expect(state()[5]).toBe('Bad credentials')
    cleanup()
  })

  it('toggles password visibility', () => {
    mount(<Form />)
    expect(state()[6]).toBe('masked')

    act(() => screen.getByTestId('toggle').click())

    expect(state()[6]).toBe('visible')
    cleanup()
  })

  it('seeds from the options, for a prefilled or test form', () => {
    const Seeded = () => {
      const form = useOAuthForm({ username: 'preset', password: 'pw' })
      return <span data-testid="seeded">{`${form.username.value}|${form.valid}`}</span>
    }
    mount(<Seeded />)

    expect(screen.getByTestId('seeded').textContent).toBe('preset|true')
    cleanup()
  })
})
