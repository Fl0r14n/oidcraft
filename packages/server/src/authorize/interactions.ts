import { randomString } from '@oidcraft/core'
import type { ResolvedConfig } from '../config'
import { OAuthError } from '../errors'
import type { InteractionCompletion, InteractionKind, InteractionRequest, InteractionResult } from '../interaction'
import { startSession } from '../session/session'
import type { Grant } from '../types'
import type { AuthorizationRequest } from './authorization'
import { detailsConsentId, type ResponseTarget } from './authorization'
import { pushParameters } from './par'

const load = async (config: ResolvedConfig, id: string) => {
  const artifact = await config.adapter.artifacts.find('interaction', id)
  if (!artifact) throw new OAuthError('invalid_request', { description: 'this interaction is unknown or has expired', status: 404 })
  return {
    artifact,
    request: artifact.payload.request as unknown as AuthorizationRequest,
    kind: artifact.payload.interactionKind as InteractionKind
  }
}

export const interactions = (config: ResolvedConfig) => ({
  async find(id: string): Promise<InteractionRequest> {
    const { artifact, request, kind } = await load(config, id)
    if (kind === 'logout') return logoutView(id, artifact.clientId, artifact.expiresAt)
    if (artifact.payload.device) return deviceView(id, artifact.clientId, artifact.payload.device as DeviceLogin, artifact.expiresAt)
    const client = await config.adapter.clients.find(request.clientId)
    return {
      id,
      kind,
      clientId: request.clientId,
      scopes: request.scopes,
      prompt: request.prompt,
      loginHint: request.loginHint,
      acrValues: request.acrValues,
      uiLocales: request.uiLocales,
      maxAge: request.maxAge,
      upstreamProviders: client?.upstreamProviders,
      upstream: artifact.payload.upstream as InteractionRequest['upstream'],
      authorizationDetails: request.authorizationDetails,
      expiresAt: artifact.expiresAt
    }
  },

  /**
   * Applies the answer to durable state and sends the browser back to the authorization endpoint,
   * which re-evaluates the original request against it and may demand another interaction (FR-I2).
   * The result is never carried in the redirect: state that decides an authorization does not
   * belong in a URL the user can edit.
   */
  async complete(id: string, outcome: InteractionResult): Promise<InteractionCompletion> {
    const { artifact, request, kind } = await load(config, id)
    if (kind === 'logout') return confirmLogout(config, id, artifact.payload, outcome)
    if (artifact.payload.device) return completeDeviceLogin(config, id, artifact.clientId, artifact.payload.device as DeviceLogin, outcome)
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
      throw new OAuthError('invalid_request', { description: 'this interaction was already completed', status: 404 })
    }

    if (outcome.error) {
      await config.adapter.artifacts.destroy('interaction', id)
      // A form_post response cannot be a URL handed to the host, so every error goes back through the
      // authorization endpoint, which delivers it in the mode the client asked for.
      const responseId = randomString()
      const target: ResponseTarget = { redirectUri: request.redirectUri, responseMode: request.responseMode, state: request.state }
      await config.adapter.artifacts.upsert({
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

    if (outcome.consent) {
      if (!accountId) throw new OAuthError('invalid_request', { description: 'consent was given without a logged-in account' })

      const previous = await config.adapter.grants.findByAccountAndClient(accountId, request.clientId)
      const grant: Grant = {
        id: previous?.id ?? randomString(),
        accountId,
        clientId: request.clientId,
        // FR-I4: consent accumulates, so a returning user is not re-asked for what they already allowed.
        scopes: [...new Set([...(previous?.scopes ?? []), ...outcome.consent.scopes])],
        claims: previous?.claims ?? [],
        resources: previous?.resources ?? {},
        createdAt: previous?.createdAt ?? new Date()
      }
      await config.adapter.grants.upsert(grant)

      if (requestedDetails) {
        await config.adapter.artifacts.upsert({
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

    return { redirectTo: await authorizationUrl(config, request, Boolean(outcome.login)), setCookie }
  }
})

const logoutView = (id: string, clientId: string, expiresAt: Date): InteractionRequest => ({
  id,
  kind: 'logout',
  clientId,
  scopes: [],
  prompt: [],
  loginHint: undefined,
  acrValues: undefined,
  uiLocales: undefined,
  maxAge: undefined,
  upstreamProviders: undefined,
  upstream: undefined,
  authorizationDetails: undefined,
  expiresAt
})

type DeviceLogin = { userCode: string; scopes: string[] }

const deviceView = (id: string, clientId: string, device: DeviceLogin, expiresAt: Date): InteractionRequest => ({
  ...logoutView(id, clientId, expiresAt),
  kind: 'login',
  scopes: device.scopes
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
    throw new OAuthError('invalid_request', { description: 'a device sign-in is completed only by signing in', status: 400 })
  }
  if (!(await config.adapter.artifacts.consume('interaction', id))) {
    throw new OAuthError('invalid_request', { description: 'this interaction was already completed', status: 404 })
  }
  const { cookie } = await startSession(config, outcome.login, clientId)
  await config.adapter.artifacts.destroy('interaction', id)
  const url = new URL(`${config.issuer}${config.routes.deviceVerification}`)
  url.searchParams.set('user_code', device.userCode)
  return { redirectTo: url.toString(), setCookie: cookie }
}

/** The person confirmed; end-session runs again with a single-use proof of it (OIDC RP-Initiated Logout 1.0 §2). */
const confirmLogout = async (config: ResolvedConfig, id: string, payload: Record<string, unknown>, outcome: InteractionResult) => {
  if (!outcome.logout) {
    throw new OAuthError('invalid_request', { description: 'a logout interaction is completed only by confirming it', status: 400 })
  }
  if (!(await config.adapter.artifacts.consume('interaction', id))) {
    throw new OAuthError('invalid_request', { description: 'this interaction was already completed', status: 404 })
  }
  const url = new URL(`${config.issuer}${config.routes.endSession}`)
  url.searchParams.set('logout', id)
  if (typeof payload.state === 'string') url.searchParams.set('state', payload.state)
  return { redirectTo: url.toString(), setCookie: undefined }
}

const authorizationUrl = async (config: ResolvedConfig, request: AuthorizationRequest, loggedIn: boolean) => {
  const url = new URL(`${config.issuer}${config.routes.authorization}`)
  const params = new URLSearchParams(request.raw)
  // prompt has just been satisfied, and replaying it loops forever.
  params.delete('prompt')
  // acr_values was put to the login that just ran; what it achieved is the answer, and the ID token
  // reports it (OIDC Core §3.1.2.1, FR-C16). Replaying an unmeetable one loops forever too.
  if (loggedIn) params.delete('acr_values')
  // max_age was measured against the login that just ran; replaying it loops whenever it is shorter
  // than the round trip, which max_age=0 always is (OIDC Core §3.1.2.1).
  if (loggedIn) params.delete('max_age')
  // A pushed or signed request was already resolved into these parameters; replaying the reference
  // would consume it a second time (RFC 9126 §4).
  params.delete('request_uri')
  params.delete('request')
  url.search = request.pushed
    ? new URLSearchParams({ client_id: request.clientId, request_uri: await pushParameters(config, request.clientId, params) }).toString()
    : params.toString()
  return url.toString()
}
