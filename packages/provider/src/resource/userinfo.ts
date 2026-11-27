import type { Client } from '@oidcraft/adapter'
import { CompactEncrypt, importJWK, type JWK } from 'jose'
import { publicUrl, type ResolvedConfig } from '../config'
import type { ClientCertificate } from '../context'
import type { Caller } from '../cors'
import { OAuthError } from '../errors'
import { readForm } from '../form'
import { signerFor } from '../keys/signer'
import { subjectFor } from '../token/subjects'
import { assertAccessToken, refused } from './verify'

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
  const form = request.method === 'POST' ? await readForm(request) : undefined
  // FR-C5: a token for a resource is that resource's. Served here, the resource server holding it could read the profile.
  const { artifact, client, scheme } = await assertAccessToken(
    config,
    request,
    { htu: publicUrl(config, request), form },
    clientCertificate,
    caller
  )
  const { accountId } = artifact
  if (!accountId) throw refused('invalid_token', 'this access token identifies no end user', { scheme })

  const { scopes } = artifact.payload
  if (!scopes.includes('openid')) throw refused('invalid_token', 'the access token does not carry the openid scope', { scheme })

  const claims = await config.adapter.accounts.claims(accountId, scopes, artifact.payload.claims ?? [])
  // OIDC Core §5.3.2: the same sub the ID token carried, or the client cannot match them up.
  const subject = artifact.payload.subject ?? (await subjectFor(config, client, accountId))

  if (client.userinfoSignedResponseAlg || client.userinfoEncryptedResponseAlg) {
    return new Response(await asJwt(config, client, subject, claims ?? {}), {
      headers: { 'content-type': 'application/jwt', 'cache-control': 'no-store' }
    })
  }

  // The account store supplies claims, not the subject: a `sub` from it would undo a pairwise one (FR-C18).
  return Response.json({ ...claims, sub: subject }, { headers: { 'cache-control': 'no-store' } })
}
