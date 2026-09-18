import { authorizationUrl } from './authorization'
import { assertSecure } from './secure'
import { type OAuthFetch, type OAuthFunctions, OAuthType, type TokenAuthMethod } from './types'

const FORM_HEADERS = {
  'Content-Type': 'application/x-www-form-urlencoded',
  Accept: 'application/json'
}

type Credentials = { clientId?: string; clientSecret?: string; tokenAuthMethod?: TokenAuthMethod }

const form = (fields: Record<string, string | undefined>) => {
  const body = new URLSearchParams()
  for (const [key, value] of Object.entries(fields)) {
    if (value !== undefined) {
      body.set(key, value)
    }
  }
  return body
}

/** RFC 6749 §2.3.1: the Basic variant form-urlencodes each half before the base64, which is the
 * difference between working and not for any secret containing `+`, `/`, `:` or a space. */
const credentials = (config: Credentials | undefined) => {
  const { clientId, clientSecret, tokenAuthMethod = 'client_secret_post' } = config || {}
  if (tokenAuthMethod === 'none') return { fields: { client_id: clientId }, headers: undefined }
  if (tokenAuthMethod === 'client_secret_basic' && clientId && clientSecret !== undefined) {
    const basic = btoa(`${encodeURIComponent(clientId)}:${encodeURIComponent(clientSecret)}`)
    return { fields: {}, headers: { Authorization: `Basic ${basic}` } }
  }
  return { fields: { client_id: clientId, client_secret: clientSecret }, headers: undefined }
}

const request = async (url: string, init?: RequestInit, fetchImpl: OAuthFetch = fetch): Promise<any> => {
  try {
    const response = await fetchImpl(url, init)
    return await response.json().catch(() => undefined)
  } catch {
    return undefined
  }
}

const post = (url: string, fields: Record<string, string | undefined>, headers?: Record<string, string>) =>
  request(url, { method: 'POST', headers: { ...FORM_HEADERS, ...headers }, body: form(fields) })

/** The secure check sits outside `request`'s catch on purpose, so a misconfigured scheme throws
 * rather than becoming another `undefined` the caller has to guess the cause of. */
const authenticatedPost = (
  url: string,
  fields: Record<string, string | undefined>,
  config: (Credentials & { allowInsecure?: boolean }) | undefined
) => {
  assertSecure(url, config?.allowInsecure)
  const { fields: auth, headers } = credentials(config)
  return post(url, { ...auth, ...fields }, headers)
}

export const defaultOAuthFunctions: OAuthFunctions = {
  authorizationUrl,

  refresh: async (token, config) => {
    const { tokenPath, scope } = config || {}
    const { refresh_token, type } = token || {}
    if (!refresh_token || !tokenPath) return token
    const refreshed = await authenticatedPost(tokenPath, { grant_type: 'refresh_token', refresh_token, scope }, config)
    return (refreshed && { ...refreshed, type }) || token
  },

  revoke: async (token, config) => {
    const { revokePath } = config || {}
    if (!revokePath) return
    const { access_token, refresh_token } = token || {}
    // both, and in this order: an IdP that only honours one still ends up with nothing usable
    for (const [value, hint] of [
      [access_token, 'access_token'],
      [refresh_token, 'refresh_token']
    ] as const) {
      if (value) {
        await authenticatedPost(revokePath, { token: value, token_type_hint: hint }, config)
      }
    }
  },

  authorize: async (token, config) => {
    const { tokenPath, scope } = config || {}
    const { code, redirect_uri, code_verifier } = token || {}
    if (!code || !tokenPath) return token
    const exchanged = await authenticatedPost(
      tokenPath,
      { code, redirect_uri, grant_type: 'authorization_code', scope, code_verifier },
      config
    )
    return (exchanged && { ...exchanged, type: OAuthType.AUTHORIZATION_CODE }) || token
  },

  clientCredentialLogin: async config => {
    const { tokenPath, scope } = config || {}
    if (!tokenPath) return undefined
    const token = await authenticatedPost(tokenPath, { grant_type: OAuthType.CLIENT_CREDENTIAL, scope }, config)
    return (token && { ...token, type: OAuthType.CLIENT_CREDENTIAL }) || undefined
  },

  resourceOwnerLogin: async (parameters, config) => {
    const { tokenPath, clientId, scope } = config || {}
    const { username, password } = parameters
    if (!tokenPath || !clientId) return undefined
    const token = await authenticatedPost(tokenPath, { grant_type: OAuthType.RESOURCE, scope, username, password }, config)
    return (token && { ...token, type: OAuthType.RESOURCE }) || undefined
  },

  // OIDC Discovery 1.0 §4.1 defines no query parameters here, and Entra answers a `client_id` with
  // AADSTS1004008 rather than a document
  openIdConfiguration: async config => {
    const { issuerPath, allowInsecure } = config || {}
    if (!issuerPath) return undefined
    const url = assertSecure(`${issuerPath}/.well-known/openid-configuration`, allowInsecure)
    return (await request(url, { headers: { Accept: 'application/json' } })) || undefined
  },

  userInfo: async (config, oauthFetch = fetch) => {
    const { userPath, allowInsecure } = config || {}
    if (!userPath) return undefined
    assertSecure(userPath, allowInsecure)
    // the instance's authorized fetch by default, so the bearer is attached
    return (await request(userPath, { headers: { Accept: 'application/json' } }, oauthFetch)) || undefined
  },

  // Left on Basic unconditionally: RFC 7662 §2.1 only requires *some* client authentication, this is
  // what every provider tested accepts, and `tokenAuthMethod` was added for the token endpoint, where
  // the choice actually varies. Changing it here would move an endpoint nothing asked about.
  introspect: async (token, config) => {
    const { introspectionPath, clientId, clientSecret, allowInsecure } = config || {}
    const { access_token } = token || {}
    if (!introspectionPath || !access_token || !clientId) return undefined
    assertSecure(introspectionPath, allowInsecure)
    return (
      (await post(introspectionPath, { token: access_token }, { Authorization: `Basic ${btoa(`${clientId}:${clientSecret}`)}` })) ||
      undefined
    )
  }
}

export const resolveOAuthFunctions = (functions?: Partial<OAuthFunctions>): OAuthFunctions => ({ ...defaultOAuthFunctions, ...functions })
