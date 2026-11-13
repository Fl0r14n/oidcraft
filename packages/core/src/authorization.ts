import { calculatePKCECodeChallenge, randomNonce, randomPKCECodeVerifier, randomState } from './random'
import { assertSecure } from './secure'
import type { OAuthFunctions, OpenIdConfig } from './types'

const nonceFor = (scope: string) => (scope.indexOf('openid') > -1 ? randomNonce() : undefined)

/** Builds the authorization URL and the handoff to keep until the redirect returns; redirects and stores nothing. */
export const authorizationUrl: OAuthFunctions['authorizationUrl'] = async (parameters, config) => {
  const { authorizePath, clientId, scope = '', pkce: usePkce, allowInsecure } = (config || {}) as OpenIdConfig
  assertSecure(authorizePath, allowInsecure)
  const nonce = nonceFor(scope)
  const code_verifier = (usePkce && randomPKCECodeVerifier()) || undefined
  const state = parameters.state ?? randomState()
  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: parameters.redirectUri,
    response_type: parameters.responseType,
    scope,
    state
  })
  if (parameters.accessType) {
    params.set('access_type', parameters.accessType)
  }
  if (parameters.prompt) {
    params.set('prompt', parameters.prompt)
  }
  if (nonce) {
    params.set('nonce', nonce)
  }
  if (code_verifier) {
    params.set('code_challenge', await calculatePKCECodeChallenge(code_verifier))
    params.set('code_challenge_method', 'S256')
  }
  for (const [key, value] of Object.entries(parameters.extras || {})) {
    if (value !== undefined) {
      params.set(key, value)
    }
  }
  return {
    url: `${authorizePath}${authorizePath.includes('?') ? '&' : '?'}${params}`,
    handoff: {
      redirect_uri: parameters.redirectUri,
      state,
      ...(nonce && { nonce }),
      ...(code_verifier && { code_verifier })
    }
  }
}
