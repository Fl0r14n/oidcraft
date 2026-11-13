import { randomString } from '@oidcraft/core'
import type { ResolvedConfig } from '../config'
import { OAuthError } from '../errors'
import type { InteractionCompletion, InteractionRequest, InteractionResult } from '../interaction'
import { type DeviceLogin, type InteractionPayload, readArtifact, writeArtifact } from '../payloads'
import { assertSameBrowser } from '../session/browser'
import { startSession } from '../session/session'
import {
  type AuthorizationRequest,
  detailsConsentId,
  essentialAcrUnmet,
  type ResponseTarget,
  requestedAcrValues,
  subjectMismatch
} from './authorization'
import { heldClaims, individuallyRequested } from './claims'
import { recordConsent } from './consent'
import { pushParameters } from './par'

const load = async (config: ResolvedConfig, id: string) => {
  const artifact = await readArtifact(config.adapter.artifacts, 'interaction', id)
  if (!artifact)
    throw new OAuthError('invalid_request', { description: 'this interaction is unknown or has expired', status: 404, spec: 'FR-I2' })
  return { artifact, payload: artifact.payload }
}

/** A session for an account the `AccountStore` cannot find would issue tokens for nobody (FR-I2). */
const knownAccount = async (config: ResolvedConfig, accountId: string) => {
  if (!(await config.adapter.accounts.find(accountId))) {
    throw new OAuthError('invalid_request', {
      description: `login names account ${accountId}, which the AccountStore does not find`,
      spec: 'FR-I2'
    })
  }
}

export const interactions = (config: ResolvedConfig) => ({
  async find(id: string): Promise<InteractionRequest> {
    const { artifact, payload } = await load(config, id)
    if (payload.interactionKind === 'logout') return logoutView(id, artifact.clientId, artifact.expiresAt)
    if ('device' in payload) return deviceView(id, artifact.clientId, payload.device, artifact.expiresAt)
    const { request, interactionKind: kind } = payload
    const client = await config.adapter.clients.find(request.clientId)
    return {
      id,
      kind,
      clientId: request.clientId,
      scopes: request.scopes,
      claims: individuallyRequested(config, request.scopes, request.claims),
      prompt: request.prompt,
      loginHint: request.loginHint,
      acrValues: requestedAcrValues(request),
      uiLocales: request.uiLocales,
      maxAge: request.maxAge,
      upstreamProviders: client?.upstreamProviders,
      upstream: payload.upstream,
      authorizationDetails: request.authorizationDetails,
      redirectUri: request.redirectUri,
      expiresAt: artifact.expiresAt
    }
  },

  /**
   * Applies the answer and sends the browser back to the authorization endpoint, which re-evaluates the
   * request and may suspend again (FR-I2). The result is never carried in the URL, where the user could edit it.
   */
  async complete(id: string, given: InteractionResult, cookie: string | null): Promise<InteractionCompletion> {
    const { artifact, payload } = await load(config, id)
    await assertSameBrowser(config, cookie, payload.browser)
    if (payload.interactionKind === 'logout') return confirmLogout(config, id, payload, given)
    if ('device' in payload) return completeDeviceLogin(config, id, artifact.clientId, payload.device, given)
    const { request } = payload
    // FR-F9: max_age went upstream with the login, so an auth_time older than it says it was not honoured.
    const outcome: InteractionResult = staleLogin(config, artifact.expiresAt, request.maxAge, given.login?.authTime)
      ? { error: { error: 'login_required', description: 'the sign-in is older than max_age allows' } }
      : ((await refusedLogin(config, request, given.login)) ?? given)
    if (outcome.consent) {
      const consented = outcome.consent.scopes
      const unasked = consented.filter(scope => !request.scopes.includes(scope))
      if (unasked.length) {
        throw new OAuthError('invalid_request', {
          description: `consent grants ${unasked.join(', ')}, which this request did not ask for`,
          spec: 'FR-I4'
        })
      }
      // All or nothing: a partial consent would be stored, then asked for again in full (FR-I4).
      const accountId = outcome.login?.accountId ?? artifact.accountId
      // Before the consume below, like every other refusal: a refused answer must not spend the interaction (FR-I2).
      if (!accountId)
        throw new OAuthError('invalid_request', { description: 'consent was given without a logged-in account', spec: 'FR-I2' })
      const held = await config.adapter.grants.findByAccountAndClient(accountId, request.clientId)
      const declined = request.scopes.filter(scope => !consented.includes(scope) && !held?.scopes.includes(scope))
      if (declined.length) {
        throw new OAuthError('invalid_request', {
          description: `consent must approve every requested scope, or answer access_denied; it leaves out ${declined.join(', ')}`,
          spec: 'FR-I4'
        })
      }
      const asked = individuallyRequested(config, request.scopes, request.claims)
      const named = outcome.consent.claims ?? []
      const unaskedClaims = named.filter(name => !asked.includes(name))
      if (unaskedClaims.length) {
        throw new OAuthError('invalid_request', {
          description: `consent grants the claims ${unaskedClaims.join(', ')}, which this request did not ask for`,
          spec: 'FR-C22'
        })
      }
      const holding = heldClaims(config, held)
      const declinedClaims = asked.filter(name => !named.includes(name) && !holding.has(name))
      if (declinedClaims.length) {
        throw new OAuthError('invalid_request', {
          description: `consent must approve every requested claim, or answer access_denied; it leaves out ${declinedClaims.join(', ')}`,
          spec: 'FR-C22'
        })
      }
    }
    if (outcome.login) await knownAccount(config, outcome.login.accountId)
    const requestedDetails = request.authorizationDetails
    if (outcome.consent && requestedDetails) {
      const approved = outcome.consent.authorizationDetails
      if (!approved || JSON.stringify(approved) !== JSON.stringify(requestedDetails)) {
        throw new OAuthError('invalid_request', {
          description: 'consent must approve every authorization detail the request carried, or answer access_denied',
          spec: 'RFC 9396 §7'
        })
      }
    }
    // A double-submitted form must not start two sessions or write two grants (FR-I2).
    if (!(await config.adapter.artifacts.consume('interaction', id))) {
      throw new OAuthError('invalid_request', { description: 'this interaction was already completed', status: 404, spec: 'FR-I2' })
    }

    if (outcome.error) {
      await config.adapter.artifacts.destroy('interaction', id)
      // A form_post response is not a URL, so every error goes back through the authorization endpoint to be delivered.
      const responseId = randomString()
      const target: ResponseTarget = { redirectUri: request.redirectUri, responseMode: request.responseMode, state: request.state }
      await writeArtifact(config.adapter.artifacts, {
        id: responseId,
        kind: 'authorization_response',
        clientId: request.clientId,
        payload: {
          target,
          values: { error: outcome.error.error, ...(outcome.error.description && { error_description: outcome.error.description }) }
        },
        expiresAt: new Date(Date.now() + config.ttl.interaction * 1000)
      })
      const url = new URL(`${config.issuer}${config.routes.authorization}`)
      url.searchParams.set('response', responseId)
      return { redirectTo: url.toString(), setCookie: undefined }
    }

    let setCookie: string | undefined
    let accountId = artifact.accountId

    if (outcome.login) {
      const started = await startSession(config, outcome.login, request.clientId)
      setCookie = started.cookie
      accountId = started.session.accountId
    }

    if (outcome.consent && accountId) {
      await recordConsent(config, accountId, request.clientId, outcome.consent.scopes, outcome.consent.claims)

      if (requestedDetails) {
        await writeArtifact(config.adapter.artifacts, {
          id: await detailsConsentId(accountId, request.clientId, requestedDetails),
          kind: 'authorization_details_consent',
          clientId: request.clientId,
          accountId,
          payload: {},
          expiresAt: new Date(Date.now() + config.ttl.interaction * 1000)
        })
      }
    }

    // Single-use: the authorization endpoint suspends again if it still cannot decide (FR-I2).
    await config.adapter.artifacts.destroy('interaction', id)

    return { redirectTo: await authorizationUrl(config, request, outcome), setCookie }
  }
})

const logoutView = (id: string, clientId: string, expiresAt: Date): InteractionRequest => ({
  id,
  kind: 'logout',
  clientId,
  scopes: [],
  claims: [],
  prompt: [],
  loginHint: undefined,
  acrValues: undefined,
  uiLocales: undefined,
  maxAge: undefined,
  upstreamProviders: undefined,
  upstream: undefined,
  authorizationDetails: undefined,
  redirectUri: undefined,
  expiresAt
})

const deviceView = (id: string, clientId: string, device: DeviceLogin, expiresAt: Date): InteractionRequest => ({
  ...logoutView(id, clientId, expiresAt),
  kind: 'login',
  scopes: device.scopes,
  claims: []
})

/** Signed in, the person goes back to the code they typed; approving it is still a separate step (FR-C7). */
const completeDeviceLogin = async (
  config: ResolvedConfig,
  id: string,
  clientId: string,
  device: DeviceLogin,
  outcome: InteractionResult
) => {
  if (!outcome.login) {
    throw new OAuthError('invalid_request', { description: 'a device sign-in is completed only by signing in', status: 400, spec: 'FR-I2' })
  }
  await knownAccount(config, outcome.login.accountId)
  if (!(await config.adapter.artifacts.consume('interaction', id))) {
    throw new OAuthError('invalid_request', { description: 'this interaction was already completed', status: 404, spec: 'FR-I2' })
  }
  const { cookie } = await startSession(config, outcome.login, clientId)
  await config.adapter.artifacts.destroy('interaction', id)
  const url = new URL(`${config.issuer}${config.routes.deviceVerification}`)
  url.searchParams.set('user_code', device.userCode)
  return { redirectTo: url.toString(), setCookie: cookie }
}

/** The person confirmed; end-session runs again with a single-use proof of it (OIDC RP-Initiated Logout 1.0 §2). */
const confirmLogout = async (
  config: ResolvedConfig,
  id: string,
  payload: Extract<InteractionPayload, { interactionKind: 'logout' }>,
  outcome: InteractionResult
) => {
  if (!outcome.logout) {
    throw new OAuthError('invalid_request', {
      description: 'a logout interaction is completed only by confirming it',
      status: 400,
      spec: 'FR-I2'
    })
  }
  if (!(await config.adapter.artifacts.consume('interaction', id))) {
    throw new OAuthError('invalid_request', { description: 'this interaction was already completed', status: 404, spec: 'FR-I2' })
  }
  const url = new URL(`${config.issuer}${config.routes.endSession}`)
  url.searchParams.set('logout', id)
  if (payload.state !== undefined) url.searchParams.set('state', payload.state)
  return { redirectTo: url.toString(), setCookie: undefined }
}

/** FR-C22: a login that misses an essential acr failed (§5.5.1.1), and one as someone other than the requested sub is no answer (§5.5.1). */
const refusedLogin = async (
  config: ResolvedConfig,
  request: AuthorizationRequest,
  login: InteractionResult['login']
): Promise<InteractionResult | undefined> => {
  if (!login) return undefined
  if (essentialAcrUnmet(request, login.acr)) {
    return { error: { error: 'access_denied', description: 'the sign-in did not reach the acr the client requires' } }
  }
  const client = request.claims?.sub === undefined ? undefined : await config.adapter.clients.find(request.clientId)
  if (client && (await subjectMismatch(config, client, request, login.accountId))) {
    return { error: { error: 'access_denied', description: 'the person who signed in is not the one the client asked for' } }
  }
  return undefined
}

const AUTH_TIME_SKEW = 30

/** A login that reports authenticating before the request arrived, by more than `max_age` (OIDC Core §3.1.2.1). */
const staleLogin = (config: ResolvedConfig, expiresAt: Date, maxAge: number | undefined, authTime: Date | undefined) => {
  if (maxAge === undefined || !authTime) return false
  const requestedAt = expiresAt.getTime() - config.ttl.interaction * 1000
  return authTime.getTime() < requestedAt - (maxAge + AUTH_TIME_SKEW) * 1000
}

// An answered prompt must go, or the replay loops; an unanswered one must stay, or it is skipped (FR-I5, OIDC Core §3.1.2.1).
const ANSWERS = { login: ['login', 'select_account'], consent: ['consent'] } as const

const authorizationUrl = async (config: ResolvedConfig, request: AuthorizationRequest, outcome: InteractionResult) => {
  const loggedIn = Boolean(outcome.login)
  const url = new URL(`${config.issuer}${config.routes.authorization}`)
  const params = new URLSearchParams(request.raw)
  const answered = new Set<string>([...(outcome.login ? ANSWERS.login : []), ...(outcome.consent ? ANSWERS.consent : [])])
  const remaining = (params.get('prompt') ?? '').split(' ').filter(value => value && !answered.has(value))
  if (remaining.length) params.set('prompt', remaining.join(' '))
  else params.delete('prompt')
  // The login just run answered acr_values and the ID token reports what it achieved (FR-C16); replaying it can loop.
  if (loggedIn) params.delete('acr_values')
  // Replaying max_age loops whenever it is shorter than the round trip, as max_age=0 always is (OIDC Core §3.1.2.1).
  if (loggedIn) params.delete('max_age')
  // Already resolved into these parameters; replaying the reference would consume it twice (RFC 9126 §4).
  params.delete('request_uri')
  params.delete('request')
  url.search = request.pushed
    ? new URLSearchParams({ client_id: request.clientId, request_uri: await pushParameters(config, request.clientId, params) }).toString()
    : params.toString()
  return url.toString()
}
