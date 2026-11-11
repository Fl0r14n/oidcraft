import { describe, expect, test } from 'bun:test'
import { OAuthError } from './errors'

// RFC 6749 §5.2.
describe('error responses', () => {
  test('error_uri is a URI, linking the RFC the error cites', () => {
    const { body } = new OAuthError('invalid_grant', { spec: 'RFC 9700 §4.8.2, OAuth 2.1 §4.1.3' })
    expect(body.error_uri).toBe('https://www.rfc-editor.org/rfc/rfc9700#section-4.8.2')
  })

  test('a citation that names no RFC is left out rather than sent as a non-URI', () => {
    expect(new OAuthError('invalid_request', { spec: 'OIDC Core §3.1.2.6' }).body).not.toHaveProperty('error_uri')
  })

  test('error_description carries only the characters the RFC allows', () => {
    const { body } = new OAuthError('invalid_request', { description: 'redirect_uri "https://é.example\\x" is not registered' })
    expect(body.error_description).toBe('redirect_uri ?https://?.example?x? is not registered')
  })
})
