import type { ResolvedConfig } from '../config'
import { verifyDpopProof } from '../dpop'
import { OAuthError } from '../errors'

const presentedToken = (request: Request, form: URLSearchParams | undefined) => {
  const header = request.headers.get('authorization')
  if (header?.toLowerCase().startsWith('bearer ')) return { token: header.slice(7).trim(), scheme: 'bearer' as const }
  if (header?.toLowerCase().startsWith('dpop ')) return { token: header.slice(5).trim(), scheme: 'dpop' as const }
  const body = form?.get('access_token')
  return body ? { token: body, scheme: 'bearer' as const } : undefined
}

const unauthorized = (description: string, scheme = 'Bearer', code: 'invalid_request' | 'invalid_grant' = 'invalid_grant') =>
  new OAuthError(code, {
    description,
    spec: 'RFC 6750 §3.1',
    status: 401,
    headers: { 'www-authenticate': `${scheme} error="invalid_token", error_description="${description}"` }
  })

/** Claims are resolved now, through the adapter — never served from a copy cached at login (FR-C5). */
export const userinfoEndpoint = async (config: ResolvedConfig, request: Request) => {
  const form = request.method === 'POST' ? new URLSearchParams(await request.text()) : undefined
  const presented = presentedToken(request, form)
  if (!presented) throw unauthorized('no access token was presented', 'Bearer', 'invalid_request')

  const artifact = await config.adapter.artifacts.find('access_token', presented.token)
  if (!artifact || artifact.consumedAt) throw unauthorized('the access token is unknown or expired')
  if (!artifact.accountId) throw unauthorized('this access token identifies no end user')

  const boundTo = (artifact.payload.cnf as { jkt?: string } | undefined)?.jkt
  if (boundTo) {
    // RFC 9449 §7.1: a bound token presented as a Bearer is exactly the theft this prevents.
    if (presented.scheme !== 'dpop') {
      throw unauthorized('this access token is DPoP-bound and must be presented with the DPoP scheme', 'DPoP')
    }
    await verifyDpopProof(config, request, { accessToken: presented.token, expectedJkt: boundTo })
  }

  const scopes = (artifact.payload.scopes as string[] | undefined) ?? []
  if (!scopes.includes('openid')) throw unauthorized('the access token does not carry the openid scope')

  const claims = await config.adapter.accounts.claims(artifact.accountId, scopes, [])
  // OIDC Core §5.3.2: the same sub the ID token carried, or the client cannot match them up.
  const subject = (artifact.payload.subject as string | undefined) ?? artifact.accountId
  return Response.json({ sub: subject, ...claims }, { headers: { 'cache-control': 'no-store' } })
}
