import type { Client, Grant, Session } from '@oidcraft/adapter'
import { randomString } from '@oidcraft/core'
import type { ResolvedConfig } from '../config'
import { OAuthError } from '../errors'
import { readArtifact, type Stored, writeArtifact } from '../payloads'
import { isFresh } from '../session/session'
import { subjectFor } from '../token/subjects'
import { selectUpstream } from '../upstreams/selection'
import type { ClaimsRequest, RequestedClaims } from './claims'
import { detailsConsentId, outstandingConsent } from './consent'
import type { AuthorizationRequest } from './request'

/** Every acr the login is asked for, by `acr_values` or by the `claims` parameter, for the screens and the upstream (FR-C22). */
export const requestedAcrValues = (request: Pick<AuthorizationRequest, 'acrValues' | 'claims' | 'defaultAcrValues'>) => {
  const values = [...new Set([...(request.acrValues ?? []), ...(request.claims?.acr?.values ?? []), ...(request.defaultAcrValues ?? [])])]
  return values.length ? values : undefined
}

/** §5.5.1.1: an essential acr is a requirement on the login, which only an acr among its values meets. */
export const essentialAcrUnmet = (request: Pick<AuthorizationRequest, 'claims'>, acr: string | undefined) => {
  const required = request.claims?.acr
  return Boolean(required?.essential && (!acr || !required.values.includes(acr)))
}

/** §5.5.1: a request naming its subject is answered for that person or no one. */
export const subjectMismatch = async (config: ResolvedConfig, client: Client, request: AuthorizationRequest, accountId: string) =>
  request.claims?.sub !== undefined && (await subjectFor(config, client, accountId)) !== request.claims.sub

export type AuthorizationOutcome =
  | { kind: 'response'; values: Record<string, string> }
  | { kind: 'interaction'; id: string; reason: 'login' | 'consent' }

// Suspends what it cannot decide (FR-I1); `prompt=none` turns every suspension into an error (OIDC Core §3.1.2.6).
export const authorize = async (
  config: ResolvedConfig,
  request: AuthorizationRequest,
  session: Session | undefined,
  client: Client,
  browser: string
): Promise<AuthorizationOutcome> => {
  // RFC 9470: an unmet acr means re-authenticating, never a token that quietly falls short.
  const acrUnmet =
    Boolean(request.acrValues?.length && (!session?.acr || !request.acrValues.includes(session.acr))) ||
    essentialAcrUnmet(request, session?.acr)
  // FR-I5: select_account asks which identity to use, so it goes to the login screen even with a session.
  const needsLogin =
    !session ||
    request.prompt.includes('login') ||
    request.prompt.includes('select_account') ||
    !isFresh(session, request.maxAge) ||
    acrUnmet ||
    (await subjectMismatch(config, client, request, session.accountId))

  if (needsLogin) {
    if (request.prompt.includes('none')) {
      throw new OAuthError('login_required', { description: 'no usable session and prompt=none', spec: 'OIDC Core §3.1.2.6' })
    }
    return { kind: 'interaction', id: await suspend(config, request, 'login', browser, client), reason: 'login' }
  }

  const grant = await config.adapter.grants.findByAccountAndClient(session.accountId, request.clientId)
  const { scopes, claims } = outstandingConsent(config, request, grant)
  const outstanding = [...scopes, ...claims]
  const detailsConsent = request.authorizationDetails
    ? await detailsConsentId(session.accountId, request.clientId, request.authorizationDetails)
    : undefined
  if (detailsConsent && !(await readArtifact(config.adapter.artifacts, 'authorization_details_consent', detailsConsent))) {
    outstanding.push('authorization_details')
  }

  if (!grant || outstanding.length || request.prompt.includes('consent')) {
    if (request.prompt.includes('none')) {
      throw new OAuthError('consent_required', {
        description: `consent is needed for: ${outstanding.join(', ') || 'a re-confirmation'}`,
        spec: 'OIDC Core §3.1.2.6'
      })
    }
    return { kind: 'interaction', id: await suspend(config, request, 'consent', browser, client, session), reason: 'consent' }
  }

  // Spent here, atomically, so one approval yields one code however many replays race for it.
  if (detailsConsent && !(await config.adapter.artifacts.consume('authorization_details_consent', detailsConsent))) {
    if (request.prompt.includes('none')) {
      throw new OAuthError('consent_required', {
        description: 'the authorization details approval was already spent',
        spec: 'OIDC Core §3.1.2.6'
      })
    }
    return { kind: 'interaction', id: await suspend(config, request, 'consent', browser, client, session), reason: 'consent' }
  }

  return { kind: 'response', values: await issueCode(config, request, session, grant) }
}

const suspend = async (
  config: ResolvedConfig,
  request: AuthorizationRequest,
  kind: 'login' | 'consent',
  browser: string,
  client: Client,
  session?: Session
) => {
  const id = randomString()
  // FR-F4: the provider picks the upstream and the host makes the round trip; undecided, the candidates go to the screen, never a guess.
  const upstream =
    kind === 'login' && config.upstreams.length
      ? selectUpstream(config.upstreams, {
          loginHint: request.loginHint,
          acrValues: requestedAcrValues(request),
          allowed: client.allowedUpstreams
        })
      : undefined

  const artifact: Stored<'interaction'> = {
    id,
    kind: 'interaction',
    clientId: request.clientId,
    ...(session && { accountId: session.accountId }),
    payload: {
      request,
      interactionKind: kind,
      browser,
      ...(upstream && {
        upstream: { chosen: upstream.chosen?.id, candidates: upstream.candidates.map(provider => provider.id) }
      })
    },
    expiresAt: Date.now() + config.ttl.interaction * 1000
  }
  await writeArtifact(config.adapter.artifacts, artifact)
  return id
}

const released = (claims: ClaimsRequest | undefined): RequestedClaims | undefined =>
  claims && (claims.userinfo.length || claims.idToken.length) ? { userinfo: claims.userinfo, idToken: claims.idToken } : undefined

const issueCode = async (config: ResolvedConfig, request: AuthorizationRequest, session: Session, grant: Grant) => {
  const code = randomString()
  const claims = released(request.claims)
  await writeArtifact(config.adapter.artifacts, {
    id: code,
    kind: 'authorization_code',
    clientId: request.clientId,
    accountId: session.accountId,
    grantId: grant.id,
    familyId: randomString(),
    payload: {
      redirectUri: request.redirectUri,
      codeChallenge: request.codeChallenge,
      scopes: request.scopes,
      sessionId: session.id,
      ...(request.nonce && { nonce: request.nonce }),
      ...(request.authorizationDetails && { authorizationDetails: request.authorizationDetails }),
      ...(request.resources.length && { resources: request.resources }),
      ...(request.dpopJkt && { dpopJkt: request.dpopJkt }),
      ...(claims && { claims })
    },
    expiresAt: Date.now() + config.ttl.authorizationCode * 1000
  })
  // FR-C14: unconditional, so a client can tell which provider answered.
  return { code, iss: config.issuer }
}
