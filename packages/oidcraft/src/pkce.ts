import { OAuthError } from './errors'
import { base64url, sha256 } from './random'

/** FR-C3: `plain` is not accepted, from anyone, ever. */
export const CODE_CHALLENGE_METHODS = ['S256'] as const

const MIN = 43
const MAX = 128

export const assertChallenge = (challenge: string | null, method: string | null) => {
  if (!challenge) {
    throw new OAuthError('invalid_request', {
      description: 'code_challenge is required: PKCE is mandatory for every client, public or confidential',
      spec: 'RFC 7636 §4.3, RFC 9700 §2.1.1'
    })
  }
  if (method !== 'S256') {
    throw new OAuthError('invalid_request', {
      description: `code_challenge_method must be S256, got ${method ?? 'none'}`,
      spec: 'RFC 7636 §4.3'
    })
  }
  return challenge
}

export const verifyChallenge = async (verifier: string | null, challenge: string) => {
  if (!verifier) {
    throw new OAuthError('invalid_grant', { description: 'code_verifier is required', spec: 'RFC 7636 §4.5' })
  }
  if (verifier.length < MIN || verifier.length > MAX) {
    throw new OAuthError('invalid_grant', { description: `code_verifier must be ${MIN}-${MAX} characters`, spec: 'RFC 7636 §4.1' })
  }
  if (base64url(await sha256(verifier)) !== challenge) {
    throw new OAuthError('invalid_grant', { description: 'code_verifier does not match the code_challenge', spec: 'RFC 7636 §4.6' })
  }
}
