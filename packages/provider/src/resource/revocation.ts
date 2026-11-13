import { authenticateClient } from '../clients/authenticate'
import type { ResolvedConfig } from '../config'
import type { ClientCertificate } from '../context'
import type { Caller } from '../cors'
import { OAuthError } from '../errors'
import { findPresented } from '../token/access-token'
import { revokeFamily } from '../token/family'

type Revocable = 'access_token' | 'refresh_token'

const REVOCABLE: Revocable[] = ['refresh_token', 'access_token']

const order = (hint: string | null): Revocable[] => (hint === 'access_token' ? ['access_token', 'refresh_token'] : REVOCABLE)

// RFC 7009 §2.2: an unknown token, or someone else's, is a 200 with nothing revoked, or this is an oracle for which exist.
export const revocationEndpoint = async (
  config: ResolvedConfig,
  request: Request,
  certificate?: ClientCertificate | undefined,
  caller: Caller = {}
) => {
  const form = new URLSearchParams(await request.text())
  const { client } = await authenticateClient(config, form, request.headers, certificate, caller)

  const presented = form.get('token')
  if (!presented) throw new OAuthError('invalid_request', { description: 'token is required', spec: 'RFC 7009 §2.1' })

  const ok = new Response(null, { status: 200, headers: { 'cache-control': 'no-store' } })

  for (const kind of order(form.get('token_type_hint'))) {
    const artifact = await findPresented(config, kind, presented)
    if (!artifact || artifact.clientId !== client.clientId) continue

    // A refresh token takes its family with it; the same app on another device, and the consent, stay (FR-C8, FR-I4).
    if (kind === 'refresh_token' && (artifact.familyId || artifact.grantId)) {
      await revokeFamily(config, artifact)
    } else {
      await config.adapter.artifacts.destroy(kind, artifact.id)
    }
    return ok
  }

  return ok
}
