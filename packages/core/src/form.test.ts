import { describe, expect, it } from 'bun:test'
import { oauthFieldError, oauthFieldErrors, oauthFormView } from './form'

describe('oauthFieldError', () => {
  it('is the one rule both halves of the protocol validate against', () => {
    expect(oauthFieldError('')).toBe('required')
    expect(oauthFieldError(null)).toBe('required')
    expect(oauthFieldError(undefined)).toBe('required')
    expect(oauthFieldError('ada')).toBeUndefined()
    expect(oauthFieldError('abcde', 4)).toBe('tooLong')
    expect(oauthFieldError('abcd', 4)).toBeUndefined()
  })
})

describe('oauthFieldErrors', () => {
  it('reads what a form POST hands over, which is string | null', () => {
    expect(oauthFieldErrors('ada', null)).toEqual({ username: undefined, password: 'required' })
    expect(oauthFieldErrors(null, 'secret')).toEqual({ username: 'required', password: undefined })
  })
})

describe('oauthFormView', () => {
  const state = { username: '', password: '', submitted: false, submitting: false, passwordVisible: false, dismissed: undefined }

  it('reports codes rather than sentences, so the markup owns the wording', () => {
    expect(oauthFormView(state, undefined).username.error).toBe('required')
    expect(oauthFormView({ ...state, username: 'ada' }, undefined).username.error).toBeUndefined()
  })

  it('flags a value past maxLength', () => {
    const view = oauthFormView({ ...state, username: 'abcde', password: 'x' }, undefined, 4)
    expect(view.username.error).toBe('tooLong')
    expect(view.valid).toBe(false)
  })

  // a pristine form should not shout about fields nobody has touched
  it('withholds errors until a submit has been attempted', () => {
    expect(oauthFormView(state, undefined).username.showError).toBe(false)
    expect(oauthFormView({ ...state, submitted: true }, undefined).username.showError).toBe(true)
  })

  it('shows a flow error until it is dismissed, and a different one after', () => {
    expect(oauthFormView(state, 'bad credentials').error).toBe('bad credentials')
    expect(oauthFormView({ ...state, dismissed: 'bad credentials' }, 'bad credentials').error).toBeUndefined()
    expect(oauthFormView({ ...state, dismissed: 'bad credentials' }, 'account locked').error).toBe('account locked')
  })
})
