import type { ResolvedConfig } from '../config'
import { OAuthError } from '../errors'

const bearer = (request: Request, form: URLSearchParams | undefined) => {
  const header = request.headers.get('authorization')
  if (header?.toLowerCase().startsWith('bearer ')) return header.slice(7).trim()
  return form?.get('access_token') ?? undefined
}

const unauthorized = (description: string, code: 'invalid_request' | 'invalid_grant' = 'invalid_grant') =>
  new OAuthError(code, {
    description,
    spec: 'RFC 6750 §3.1',
    status: 401,
    headers: { 'www-authenticate': `Bearer error="invalid_token", error_description="${description}"` }
  })

/** Claims are resolved now, through the adapter — never served from a copy cached at login (FR-C5). */
export const userinfoEndpoint = async (config: ResolvedConfig, request: Request) => {
  const form = request.method === 'POST' ? new URLSearchParams(await request.text()) : undefined
  const presented = bearer(request, form)
  if (!presented) throw unauthorized('no access token was presented', 'invalid_request')

  const artifact = await config.adapter.artifacts.find('access_token', presented)
  if (!artifact || artifact.consumedAt) throw unauthorized('the access token is unknown or expired')
  if (!artifact.accountId) throw unauthorized('this access token identifies no end user')

  const scopes = (artifact.payload.scopes as string[] | undefined) ?? []
  if (!scopes.includes('openid')) throw unauthorized('the access token does not carry the openid scope')

  const claims = await config.adapter.accounts.claims(artifact.accountId, scopes, [])
  return Response.json({ sub: artifact.accountId, ...claims }, { headers: { 'cache-control': 'no-store' } })
}
