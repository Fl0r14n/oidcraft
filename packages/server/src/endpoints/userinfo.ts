import { CompactEncrypt, importJWK, type JWK, SignJWT } from 'jose'
import { resolveAccessToken } from '../access-token'
import type { ResolvedConfig } from '../config'
import { verifyDpopProof } from '../dpop'
import { OAuthError } from '../errors'
import { signingKey } from '../keys'
import { certificateThumbprint } from '../mtls'
import type { Client } from '../types'

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

/**
 * A signed — and optionally encrypted — UserInfo response (OIDC Core §5.3.2, FR-C5).
 *
 * Signing is what lets a client treat these claims as coming from the provider rather than from
 * whatever answered the request; encryption keeps them from whatever sits between.
 */
const asJwt = async (config: ResolvedConfig, client: Client, subject: string, claims: Record<string, unknown>) => {
  const keys = await config.adapter.keys.active()
  const alg = client.userinfoSignedResponseAlg ?? keys[0]?.alg
  const key = alg ? signingKey(keys, alg) : undefined
  if (!key || !alg) throw new OAuthError('server_error', { description: 'no key is available to sign the UserInfo response' })

  const signed = await new SignJWT({ ...claims, sub: subject })
    .setProtectedHeader({ alg, kid: key.kid })
    .setIssuer(config.issuer)
    .setAudience(client.clientId)
    .setIssuedAt()
    .sign(await importJWK(key.privateJwk as never, alg))

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
export const userinfoEndpoint = async (config: ResolvedConfig, request: Request, clientCertificate?: { der: Uint8Array } | undefined) => {
  const form = request.method === 'POST' ? new URLSearchParams(await request.text()) : undefined
  const presented = presentedToken(request, form)
  if (!presented) throw unauthorized('no access token was presented', 'Bearer', 'invalid_request')

  const artifact = await resolveAccessToken(config, presented.token)
  if (!artifact || artifact.consumedAt) throw unauthorized('the access token is unknown or expired')
  if (!artifact.accountId) throw unauthorized('this access token identifies no end user')

  const confirmation = artifact.payload.cnf as { jkt?: string; 'x5t#S256'?: string } | undefined

  if (confirmation?.jkt) {
    // RFC 9449 §7.1: a bound token presented as a Bearer is exactly the theft this prevents.
    if (presented.scheme !== 'dpop') {
      throw unauthorized('this access token is DPoP-bound and must be presented with the DPoP scheme', 'DPoP')
    }
    await verifyDpopProof(config, request, {
      accessToken: presented.token,
      expectedJkt: confirmation.jkt,
      requireNonce: config.features.dpopNonces
    })
  }

  const boundCertificate = confirmation?.['x5t#S256']
  if (boundCertificate) {
    // RFC 8705 §3: the certificate is the second half of the credential, so no certificate is no token.
    const thumbprint = clientCertificate ? await certificateThumbprint(clientCertificate.der) : undefined
    if (thumbprint !== boundCertificate) {
      throw unauthorized('this access token is bound to a client certificate that was not presented')
    }
  }

  const scopes = (artifact.payload.scopes as string[] | undefined) ?? []
  if (!scopes.includes('openid')) throw unauthorized('the access token does not carry the openid scope')

  const claims = await config.adapter.accounts.claims(artifact.accountId, scopes, [])
  // OIDC Core §5.3.2: the same sub the ID token carried, or the client cannot match them up.
  const subject = (artifact.payload.subject as string | undefined) ?? artifact.accountId

  const client = await config.adapter.clients.find(artifact.clientId)
  if (client?.userinfoSignedResponseAlg || client?.userinfoEncryptedResponseAlg) {
    return new Response(await asJwt(config, client, subject, claims ?? {}), {
      headers: { 'content-type': 'application/jwt', 'cache-control': 'no-store' }
    })
  }

  return Response.json({ sub: subject, ...claims }, { headers: { 'cache-control': 'no-store' } })
}
