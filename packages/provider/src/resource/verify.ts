import type { EpochMillis } from '@oidcraft/adapter'
import { proofOptions, verifyDpopProof } from '../binding/dpop'
import type { ResolvedConfig } from '../config'
import type { ClientCertificate } from '../context'
import type { Caller } from '../cors'
import { errorResponse, errorText, OAuthError } from '../errors'
import { resolveAccessToken } from '../token/access-token'
import { subjectFor } from '../token/subjects'
import { protectedResourceMetadataUrl } from './protected-resource'

type Scheme = 'Bearer' | 'DPoP'

export type AccessTokenRefusal = 'invalid_request' | 'invalid_token' | 'invalid_dpop_proof' | 'use_dpop_nonce'

const SPEC: Record<AccessTokenRefusal, string> = {
  invalid_request: 'RFC 6750 §3.1',
  invalid_token: 'RFC 6750 §3.1',
  invalid_dpop_proof: 'RFC 9449 §7.1',
  use_dpop_nonce: 'RFC 9449 §9'
}

type Challenge = { scheme: Scheme; resource?: string | undefined; headers?: Record<string, string> | undefined }

// RFC 6750 §3, RFC 9449 §7.1 and §9, RFC 9728 §5.1: every refusal at a resource is a 401 naming its scheme and, for a resource, its metadata.
export const refused = (code: AccessTokenRefusal, description: string, { scheme, resource, headers }: Challenge) =>
  new OAuthError(code, {
    description,
    spec: SPEC[code],
    status: 401,
    headers: {
      ...headers,
      'www-authenticate': [
        `${scheme} error="${code}"`,
        `error_description="${errorText(description)}"`,
        ...(resource ? [`resource_metadata="${protectedResourceMetadataUrl(resource)}"`] : [])
      ].join(', ')
    }
  })

const presentedToken = (request: Request, form: URLSearchParams | undefined) => {
  const header = request.headers.get('authorization')
  if (header?.toLowerCase().startsWith('bearer ')) return { token: header.slice(7).trim(), scheme: 'Bearer' as const }
  if (header?.toLowerCase().startsWith('dpop ')) return { token: header.slice(5).trim(), scheme: 'DPoP' as const }
  const body = form?.get('access_token')
  return body ? { token: body, scheme: 'Bearer' as const } : undefined
}

export type AccessTokenCheck = {
  /** FR-C19: the resource the token must be for. Without one, only a token for no resource passes, as at UserInfo (FR-C5). */
  resource?: string | undefined
  /** The URL a DPoP proof must name, as the client saw it (NFR-S6). */
  htu: string
  /** RFC 6750 §2.2: only UserInfo reads a token from the body. */
  form?: URLSearchParams | undefined
}

/** FR-C5, FR-C13, FR-C19: what any resource, this provider's UserInfo included, checks of a presented access token. */
export const assertAccessToken = async (
  config: ResolvedConfig,
  request: Request,
  check: AccessTokenCheck,
  certificate: ClientCertificate | undefined,
  caller: Caller = {}
) => {
  const { resource } = check
  const presented = presentedToken(request, check.form)
  if (!presented) throw refused('invalid_request', 'no access token was presented', { scheme: 'Bearer', resource })

  const artifact = await resolveAccessToken(config, presented.token)
  const confirmation = artifact?.payload.cnf
  const scheme: Scheme = presented.scheme === 'DPoP' || confirmation?.jkt ? 'DPoP' : 'Bearer'
  if (!artifact || artifact.consumedAt) throw refused('invalid_token', 'the access token is unknown or expired', { scheme, resource })
  const client = await config.adapter.clients.find(artifact.clientId)
  // FR-T7: a token written while its client was being deleted can outlive the sweep; its client's absence ends it here.
  if (!client) throw refused('invalid_token', 'the client this access token was issued to no longer exists', { scheme, resource })
  caller.client = client

  const audiences = [artifact.payload.aud, artifact.payload.resource].filter(value => value !== undefined)
  if (resource ? !audiences.includes(resource) : audiences.length) {
    throw refused(
      'invalid_token',
      resource ? 'this access token was not issued for this resource' : 'this access token was issued for a resource',
      {
        scheme,
        resource
      }
    )
  }

  if (confirmation?.jkt) {
    // RFC 9449 §7.1: a bound token presented as a Bearer is exactly the theft this prevents.
    if (presented.scheme !== 'DPoP') {
      throw refused('invalid_token', 'this access token is DPoP-bound and must be presented with the DPoP scheme', { scheme, resource })
    }
    await verifyDpopProof(config, request, {
      ...proofOptions(config, request, artifact.clientId, client),
      htu: check.htu,
      accessToken: presented.token,
      expectedJkt: confirmation.jkt
    }).catch((error: unknown) => {
      if (!(error instanceof OAuthError) || (error.code !== 'invalid_dpop_proof' && error.code !== 'use_dpop_nonce')) throw error
      throw refused(error.code, error.description ?? 'the DPoP proof was refused', { scheme, resource, headers: error.headers })
    })
  }

  // RFC 8705 §3: the certificate is the second half of the credential, so no certificate is no token.
  if (confirmation?.['x5t#S256'] && certificate?.thumbprint !== confirmation['x5t#S256']) {
    throw refused('invalid_token', 'this access token is bound to a client certificate that was not presented', { scheme, resource })
  }

  return { artifact, client, scheme }
}

export type VerifyAccessTokenOptions = {
  /** FR-C19: the resource this server is. Without one, only a token issued for no resource passes. */
  resource?: string
  /** The URL the request was made to, as the client saw it, which a DPoP proof names; behind a proxy, the public one (NFR-S6). */
  url?: string
}

/** A presented access token that passed every check its resource owes it. */
export type VerifiedAccessToken = {
  clientId: string
  accountId: string | undefined
  /** FR-C18: what the token's client was told the user is called. */
  subject: string | undefined
  scopes: string[]
  grantId: string | undefined
  sessionId: string | undefined
  authorizationDetails: unknown[] | undefined
  /** RFC 8693 §4.1: who is acting for the subject. */
  actor: { client_id: string } | undefined
  expiresAt: EpochMillis
}

export type AccessTokenVerification =
  | { ok: true; token: VerifiedAccessToken }
  | { ok: false; reason: AccessTokenRefusal; description: string; response: Response }

export const verifyAccessToken = async (
  config: ResolvedConfig,
  request: Request,
  options: VerifyAccessTokenOptions,
  certificate: ClientCertificate | undefined
): Promise<AccessTokenVerification> => {
  const url = new URL(options.url ?? request.url)
  const verified = await assertAccessToken(
    config,
    request,
    { resource: options.resource, htu: `${url.origin}${url.pathname}` },
    certificate
  ).catch((error: unknown) => {
    if (error instanceof OAuthError && error.code in SPEC) {
      return {
        ok: false as const,
        reason: error.code as AccessTokenRefusal,
        description: error.description ?? '',
        response: errorResponse(error)
      }
    }
    throw error
  })
  if ('ok' in verified) return verified
  const { artifact, client } = verified
  const { accountId, payload } = artifact
  return {
    ok: true,
    token: {
      clientId: artifact.clientId,
      accountId,
      subject: accountId ? (payload.subject ?? (await subjectFor(config, client, accountId))) : undefined,
      scopes: payload.scopes,
      grantId: artifact.grantId,
      sessionId: payload.sessionId,
      authorizationDetails: payload.authorizationDetails,
      actor: payload.act,
      expiresAt: artifact.expiresAt
    }
  }
}
