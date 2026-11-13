import type { Client } from '@oidcraft/adapter'
import { CompactEncrypt, importJWK, type JWK } from 'jose'
import { proofOptions, verifyDpopProof } from '../binding/dpop'
import type { ResolvedConfig } from '../config'
import type { ClientCertificate } from '../context'
import type { Caller } from '../cors'
import { OAuthError } from '../errors'
import { signerFor } from '../keys/signer'
import { resolveAccessToken } from '../token/access-token'

const presentedToken = (request: Request, form: URLSearchParams | undefined) => {
  const header = request.headers.get('authorization')
  if (header?.toLowerCase().startsWith('bearer ')) return { token: header.slice(7).trim(), scheme: 'bearer' as const }
  if (header?.toLowerCase().startsWith('dpop ')) return { token: header.slice(5).trim(), scheme: 'dpop' as const }
  const body = form?.get('access_token')
  return body ? { token: body, scheme: 'bearer' as const } : undefined
}

const unauthorized = (description: string, scheme = 'Bearer', code: 'invalid_request' | 'invalid_token' = 'invalid_token') =>
  new OAuthError(code, {
    description,
    spec: 'RFC 6750 §3.1',
    status: 401,
    headers: { 'www-authenticate': `${scheme} error="${code}", error_description="${description}"` }
  })

const asJwt = async (config: ResolvedConfig, client: Client, subject: string, claims: Record<string, unknown>) => {
  const signer = await signerFor(config, client, client.userinfoSignedResponseAlg)
  if (!signer) throw new OAuthError('server_error', { description: 'no key is available to sign the UserInfo response' })

  const signed = await signer.sign({ ...claims, sub: subject, aud: client.clientId, iat: Math.floor(Date.now() / 1000) })

  if (!client.userinfoEncryptedResponseAlg) return signed

  const encryptionKey = (client.jwks?.keys as JWK[] | undefined)?.find(
    candidate => candidate.use === 'enc' || candidate.alg === client.userinfoEncryptedResponseAlg
  )
  if (!encryptionKey) {
    throw new OAuthError('server_error', {
      description: `client ${client.clientId} asked for an encrypted UserInfo response but registered no encryption key`
    })
  }

  return new CompactEncrypt(new TextEncoder().encode(signed))
    .setProtectedHeader({
      alg: client.userinfoEncryptedResponseAlg,
      enc: client.userinfoEncryptedResponseEnc ?? 'A128CBC-HS256',
      cty: 'JWT'
    })
    .encrypt(await importJWK(encryptionKey, client.userinfoEncryptedResponseAlg))
}

/** Claims are resolved now, through the adapter — never served from a copy cached at login (FR-C5). */
export const userinfoEndpoint = async (
  config: ResolvedConfig,
  request: Request,
  clientCertificate?: ClientCertificate | undefined,
  caller: Caller = {}
) => {
  const form = request.method === 'POST' ? new URLSearchParams(await request.text()) : undefined
  const presented = presentedToken(request, form)
  if (!presented) throw unauthorized('no access token was presented', 'Bearer', 'invalid_request')

  const artifact = await resolveAccessToken(config, presented.token)
  if (!artifact || artifact.consumedAt) throw unauthorized('the access token is unknown or expired')
  const client = await config.adapter.clients.find(artifact.clientId)
  if (client) caller.client = client
  if (!artifact.accountId) throw unauthorized('this access token identifies no end user')
  // FR-C5: a token for a resource is that resource's. Served here, the resource server holding it could read the profile.
  if (artifact.payload.aud !== undefined || artifact.payload.resource !== undefined) {
    throw unauthorized('this access token was issued for another resource; the ID token carries the claims')
  }

  const confirmation = artifact.payload.cnf

  if (confirmation?.jkt) {
    // RFC 9449 §7.1: a bound token presented as a Bearer is exactly the theft this prevents.
    if (presented.scheme !== 'dpop') {
      throw unauthorized('this access token is DPoP-bound and must be presented with the DPoP scheme', 'DPoP')
    }
    await verifyDpopProof(config, request, {
      ...proofOptions(config, request, artifact.clientId, client),
      accessToken: presented.token,
      expectedJkt: confirmation.jkt
    })
  }

  const boundCertificate = confirmation?.['x5t#S256']
  if (boundCertificate) {
    // RFC 8705 §3: the certificate is the second half of the credential, so no certificate is no token.
    if (clientCertificate?.thumbprint !== boundCertificate) {
      throw unauthorized('this access token is bound to a client certificate that was not presented')
    }
  }

  const { scopes } = artifact.payload
  if (!scopes.includes('openid')) throw unauthorized('the access token does not carry the openid scope')

  const claims = await config.adapter.accounts.claims(artifact.accountId, scopes, [])
  // OIDC Core §5.3.2: the same sub the ID token carried, or the client cannot match them up.
  const subject = artifact.payload.subject ?? artifact.accountId

  if (client?.userinfoSignedResponseAlg || client?.userinfoEncryptedResponseAlg) {
    return new Response(await asJwt(config, client, subject, claims ?? {}), {
      headers: { 'content-type': 'application/jwt', 'cache-control': 'no-store' }
    })
  }

  // The account store supplies claims, not the subject: a `sub` from it would undo a pairwise one (FR-C18).
  return Response.json({ ...claims, sub: subject }, { headers: { 'cache-control': 'no-store' } })
}
