import { authenticateClient } from '../client-auth'
import type { ResolvedConfig } from '../config'
import { verifyDpopProof } from '../dpop'
import { OAuthError } from '../errors'
import { verifyChallenge } from '../pkce'
import { token as randomToken } from '../random'
import { subjectFor } from '../subjects'
import { mintIdToken } from '../tokens'
import type { Artifact, Client, Grant, Session } from '../types'
import { consumeDeviceCode } from './device'
import { SUPPORTED_TOKEN_TYPES, TOKEN_EXCHANGE, tokenExchange } from './token-exchange'

const NO_STORE = { 'cache-control': 'no-store', pragma: 'no-cache' }

/**
 * Replaying a single-use artifact revokes the grant it belongs to, rather than merely failing.
 * A replay means the code or refresh token leaked; everything derived from it must stop working
 * (FR-T3, FR-T4, NFR-S4, RFC 9700 §4.14.2).
 */
const revokeOnReplay = async (config: ResolvedConfig, artifact: Artifact, what: string) => {
  if (artifact.grantId) await config.adapter.artifacts.revokeByGrantId(artifact.grantId)
  throw new OAuthError('invalid_grant', {
    description: `this ${what} was already used; the grant has been revoked`,
    spec: 'RFC 9700 §4.14.2'
  })
}

const scopesOf = (artifact: Artifact) => (artifact.payload.scopes as string[] | undefined) ?? []

const issueTokens = async (
  config: ResolvedConfig,
  client: Client,
  grant: Grant,
  session: Session,
  scopes: string[],
  nonce?: string,
  jkt?: string,
  authorizationDetails?: unknown[]
) => {
  const accessToken = randomToken()
  const expiresIn = config.ttl.accessToken
  // FR-C18: what this client is told the user is called, which may not be the local account id.
  const subject = await subjectFor(config, client, session.accountId)

  await config.adapter.artifacts.upsert({
    id: accessToken,
    kind: 'access_token',
    clientId: client.clientId,
    accountId: session.accountId,
    grantId: grant.id,
    // RFC 9449 §6: the confirmation claim is what makes the token useless without the key.
    payload: {
      scopes,
      sessionId: session.id,
      subject,
      ...(authorizationDetails && { authorizationDetails }),
      ...(jkt && { cnf: { jkt } })
    },
    expiresAt: new Date(Date.now() + expiresIn * 1000)
  })

  let refreshToken: string | undefined
  // Only when the client asked for it: a refresh token nobody requested is a credential nobody guards.
  if (scopes.includes('offline_access') && client.grantTypes.includes('refresh_token')) {
    refreshToken = randomToken()
    await config.adapter.artifacts.upsert({
      id: refreshToken,
      kind: 'refresh_token',
      clientId: client.clientId,
      accountId: session.accountId,
      grantId: grant.id,
      // The binding must survive rotation, or it evaporates on the first refresh (RFC 9449 §5).
      payload: { scopes, sessionId: session.id, ...(jkt && { cnf: { jkt } }) },
      expiresAt: new Date(Date.now() + config.ttl.refreshToken * 1000)
    })
  }

  const idToken = await mintIdToken(config, {
    client,
    session,
    subject,
    nonce,
    accessToken,
    claims: await config.adapter.accounts.claims(session.accountId, scopes, [])
  })

  return {
    access_token: accessToken,
    token_type: jkt ? 'DPoP' : 'Bearer',
    expires_in: expiresIn,
    scope: scopes.join(' '),
    ...(authorizationDetails && { authorization_details: authorizationDetails }),
    id_token: idToken,
    ...(refreshToken && { refresh_token: refreshToken })
  }
}

const loadGrantAndSession = async (config: ResolvedConfig, artifact: Artifact) => {
  const grant = artifact.grantId ? await config.adapter.grants.find(artifact.grantId) : undefined
  if (!grant) throw new OAuthError('invalid_grant', { description: 'the grant behind this token no longer exists' })

  const session = await config.adapter.sessions.find(artifact.payload.sessionId as string)
  if (!session) throw new OAuthError('invalid_grant', { description: 'the session behind this token has ended' })

  return { grant, session }
}

const authorizationCodeGrant = async (config: ResolvedConfig, client: Client, form: URLSearchParams, jkt?: string) => {
  const code = form.get('code')
  if (!code) throw new OAuthError('invalid_request', { description: 'code is required' })

  const artifact = await config.adapter.artifacts.find('authorization_code', code)
  if (!artifact) throw new OAuthError('invalid_grant', { description: 'the authorization code is unknown or expired' })
  if (artifact.consumedAt) await revokeOnReplay(config, artifact, 'authorization code')

  // The code was issued to one client; another presenting it is theft, not a mistake.
  if (artifact.clientId !== client.clientId) {
    await revokeOnReplay(config, artifact, 'authorization code presented by the wrong client')
  }

  const redirectUri = form.get('redirect_uri')
  if (redirectUri !== artifact.payload.redirectUri) {
    throw new OAuthError('invalid_grant', {
      description: 'redirect_uri does not match the one the code was issued for',
      spec: 'RFC 6749 §4.1.3'
    })
  }

  await verifyChallenge(form.get('code_verifier'), artifact.payload.codeChallenge as string)
  await config.adapter.artifacts.consume('authorization_code', code)

  const { grant, session } = await loadGrantAndSession(config, artifact)
  return issueTokens(
    config,
    client,
    grant,
    session,
    scopesOf(artifact),
    artifact.payload.nonce as string | undefined,
    jkt,
    artifact.payload.authorizationDetails as unknown[] | undefined
  )
}

const refreshTokenGrant = async (config: ResolvedConfig, client: Client, form: URLSearchParams, jkt?: string) => {
  const presented = form.get('refresh_token')
  if (!presented) throw new OAuthError('invalid_request', { description: 'refresh_token is required' })

  const artifact = await config.adapter.artifacts.find('refresh_token', presented)
  if (!artifact) throw new OAuthError('invalid_grant', { description: 'the refresh token is unknown or expired' })
  if (artifact.consumedAt) await revokeOnReplay(config, artifact, 'refresh token')
  if (artifact.clientId !== client.clientId) await revokeOnReplay(config, artifact, 'refresh token presented by the wrong client')

  const requested = form.get('scope')?.split(' ').filter(Boolean)
  const granted = scopesOf(artifact)
  // RFC 6749 §6: a refresh may narrow the scope, never widen it.
  const widened = requested?.filter(scope => !granted.includes(scope)) ?? []
  if (widened.length) throw new OAuthError('invalid_scope', { description: `a refresh cannot add scopes: ${widened.join(', ')}` })

  // A bound refresh token may only be presented by the key it was bound to (RFC 9449 §5).
  const boundTo = (artifact.payload.cnf as { jkt?: string } | undefined)?.jkt
  if (boundTo && boundTo !== jkt) {
    throw new OAuthError('invalid_grant', { description: 'this refresh token is bound to a different key', spec: 'RFC 9449 §5' })
  }

  // FR-T3: rotation is unconditional, which is what makes the replay rule above meaningful.
  await config.adapter.artifacts.consume('refresh_token', presented)

  const { grant, session } = await loadGrantAndSession(config, artifact)
  return issueTokens(config, client, grant, session, requested?.length ? requested : granted, undefined, boundTo ?? jkt)
}

const exchangeGrant = async (config: ResolvedConfig, client: Client, form: URLSearchParams, jkt?: string) => {
  const { decision, requestedType, subject } = await tokenExchange(config, client, form)

  const accessToken = randomToken()
  const expiresIn = config.ttl.accessToken
  await config.adapter.artifacts.upsert({
    id: accessToken,
    kind: 'access_token',
    clientId: client.clientId,
    accountId: decision.accountId,
    ...(subject.grantId && { grantId: subject.grantId }),
    payload: {
      scopes: decision.scopes,
      sessionId: subject.payload.sessionId as string,
      subject: decision.accountId,
      // RFC 8693 §4.1: who is acting, so a resource server can tell delegation from the real thing.
      ...(decision.actor && { act: { client_id: decision.actor.clientId } }),
      ...(decision.resource && { resource: decision.resource }),
      ...(decision.audience && { aud: decision.audience }),
      ...(jkt && { cnf: { jkt } })
    },
    expiresAt: new Date(Date.now() + expiresIn * 1000)
  })

  return {
    access_token: accessToken,
    issued_token_type: SUPPORTED_TOKEN_TYPES.includes(requestedType) ? requestedType : SUPPORTED_TOKEN_TYPES[0],
    token_type: jkt ? 'DPoP' : 'Bearer',
    expires_in: expiresIn,
    scope: decision.scopes.join(' ')
  }
}

const deviceCodeGrant = async (config: ResolvedConfig, client: Client, form: URLSearchParams, jkt?: string) => {
  const deviceCode = form.get('device_code')
  if (!deviceCode) throw new OAuthError('invalid_request', { description: 'device_code is required' })

  const { payload } = await consumeDeviceCode(config, deviceCode, client.clientId)
  if (!payload.grantId || !payload.sessionId) throw new OAuthError('invalid_grant', { description: 'this device code was never approved' })

  const grant = await config.adapter.grants.find(payload.grantId)
  const session = await config.adapter.sessions.find(payload.sessionId)
  if (!grant || !session) throw new OAuthError('invalid_grant', { description: 'the grant or session behind this device code is gone' })

  return issueTokens(config, client, grant, session, payload.scopes, undefined, jkt)
}

/** A client may always offer a proof; one registered for bound tokens must (RFC 9449 §5). */
const bindingFor = async (config: ResolvedConfig, client: Client, request: Request) => {
  if (!config.features.dpop) return undefined
  const offered = request.headers.has('dpop')
  if (!offered) {
    if (!client.dpopBoundAccessTokens) return undefined
    throw new OAuthError('invalid_dpop_proof', {
      description: `client ${client.clientId} is registered for DPoP-bound tokens and presented no proof`,
      spec: 'RFC 9449 §5'
    })
  }
  return (await verifyDpopProof(config, request, { requireNonce: config.features.dpopNonces })).jkt
}

export const tokenEndpoint = async (config: ResolvedConfig, request: Request) => {
  const form = new URLSearchParams(await request.text())
  const { client } = await authenticateClient(config, form, request.headers)

  const grantType = form.get('grant_type')
  if (!grantType) throw new OAuthError('invalid_request', { description: 'grant_type is required' })
  if (!client.grantTypes.includes(grantType)) {
    throw new OAuthError('unauthorized_client', { description: `client ${client.clientId} may not use grant_type ${grantType}` })
  }

  const jkt = await bindingFor(config, client, request)

  const body = await (async () => {
    switch (grantType) {
      case 'authorization_code':
        return authorizationCodeGrant(config, client, form, jkt)
      case 'refresh_token':
        return refreshTokenGrant(config, client, form, jkt)
      case 'urn:ietf:params:oauth:grant-type:device_code':
        return deviceCodeGrant(config, client, form, jkt)
      case TOKEN_EXCHANGE:
        return exchangeGrant(config, client, form, jkt)
      default:
        throw new OAuthError('unsupported_grant_type', { description: `${grantType} is not supported` })
    }
  })()

  return Response.json(body, { headers: NO_STORE })
}
