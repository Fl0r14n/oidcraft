import type { ResolvedConfig } from './config'
import type { AuthorizationRequest } from './endpoints/authorization'
import { redirectTo } from './endpoints/authorization'
import { OAuthError } from './errors'
import { token } from './random'
import { startSession } from './session'
import type { Grant } from './types'

export type InteractionKind = 'login' | 'consent'

export type InteractionView = {
  id: string
  kind: InteractionKind
  clientId: string
  scopes: string[]
  prompt: string[]
  loginHint: string | undefined
  acrValues: string[] | undefined
  uiLocales: string[] | undefined
  expiresAt: Date
}

export type InteractionOutcome = {
  login?: { accountId: string; acr?: string; amr?: string[]; idp?: string; upstreamSessionId?: string }
  consent?: { scopes: string[] }
  error?: { error: 'access_denied' | 'login_required' | 'consent_required'; description?: string }
}

export type InteractionCompletion = { redirectTo: string; setCookie: string | undefined }

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
  async find(id: string): Promise<InteractionView> {
    const { artifact, request, kind } = await load(config, id)
    return {
      id,
      kind,
      clientId: request.clientId,
      scopes: request.scopes,
      prompt: request.prompt,
      loginHint: request.loginHint,
      acrValues: request.acrValues,
      uiLocales: request.uiLocales,
      expiresAt: artifact.expiresAt
    }
  },

  /**
   * Applies the answer to durable state and sends the browser back to the authorization endpoint,
   * which re-evaluates the original request against it and may demand another interaction (FR-I2).
   * The result is never carried in the redirect: state that decides an authorization does not
   * belong in a URL the user can edit.
   */
  async complete(id: string, outcome: InteractionOutcome): Promise<InteractionCompletion> {
    const { artifact, request } = await load(config, id)

    if (outcome.error) {
      await config.adapter.artifacts.destroy('interaction', id)
      return {
        redirectTo: redirectTo(request, {
          error: outcome.error.error,
          ...(outcome.error.description && { error_description: outcome.error.description })
        }),
        setCookie: undefined
      }
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
        id: previous?.id ?? token(),
        accountId,
        clientId: request.clientId,
        // FR-I4: consent accumulates, so a returning user is not re-asked for what they already allowed.
        scopes: [...new Set([...(previous?.scopes ?? []), ...outcome.consent.scopes])],
        claims: previous?.claims ?? [],
        resources: previous?.resources ?? {},
        createdAt: previous?.createdAt ?? new Date()
      }
      await config.adapter.grants.upsert(grant)
    }

    // Single-use: the authorization endpoint suspends again if it still cannot decide (FR-I2).
    await config.adapter.artifacts.destroy('interaction', id)

    return { redirectTo: authorizationUrl(config, request), setCookie }
  }
})

const authorizationUrl = (config: ResolvedConfig, request: AuthorizationRequest) => {
  const url = new URL(config.routes.authorization, config.issuer)
  const params = new URLSearchParams(request.raw)
  // prompt is the one parameter dropped: it has just been satisfied, and replaying it loops forever.
  params.delete('prompt')
  // A pushed or signed request was already resolved into these parameters; replaying the reference
  // would consume it a second time (RFC 9126 §4).
  params.delete('request_uri')
  params.delete('request')
  url.search = params.toString()
  return url.toString()
}
