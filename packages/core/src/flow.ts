import { resolveOAuthFunctions } from './functions'
import { createIdTokenVerifier, type IdTokenVerifier } from './jwt'
import { parseRedirectParameters, type RedirectSource } from './redirect'
import { isTenantTemplate, sameIssuer } from './secure'
import {
  type AuthorizationCodeParameters,
  type AuthorizationHandoff,
  type AuthorizationRequest,
  type OAuthFunctions,
  type OAuthToken,
  OAuthType,
  type OpenIdConfig
} from './types'

export type AuthorizationOptions = {
  functions?: Partial<OAuthFunctions>
  /** reuse a verifier built once for this configuration; one is built per call otherwise */
  verifyIdToken?: IdTokenVerifier
}

const verifierFor = (config?: Partial<OpenIdConfig>, verifyIdToken?: IdTokenVerifier) =>
  verifyIdToken ??
  createIdTokenVerifier({
    jwksUri: (config as OpenIdConfig)?.jwksUri,
    issuer: (config as OpenIdConfig)?.issuer || (config as OpenIdConfig)?.issuerPath,
    audience: config?.clientId,
    allowInsecure: (config as OpenIdConfig)?.allowInsecure
  })

/** Which check a callback failed: what it says is not to be believed (FR-L2). */
export type CallbackCheck = 'state' | 'issuer' | 'nonce' | 'id_token'

/** How a callback ended (FR-L2): `refused` by the provider, `invalid` on a failed check, `unreachable` when the token endpoint was. */
export type AuthorizationResult =
  | { ok: true; token: OAuthToken }
  | { ok: false; reason: 'refused'; error: string; errorDescription?: string }
  | { ok: false; reason: 'invalid'; check: CallbackCheck; message: string }
  | { ok: false; reason: 'unreachable' }

const invalid = (check: CallbackCheck, message: string): AuthorizationResult => ({ ok: false, reason: 'invalid', check, message })

const refused = (answer: { error?: string; error_description?: string }): AuthorizationResult => ({
  ok: false,
  reason: 'refused',
  error: answer.error as string,
  ...(answer.error_description && { errorDescription: answer.error_description })
})

// RFC 6749 §10.12, RFC 9700 §4.7: without a handoff to match, a callback is unsolicited and refused.
const checkState = (parameters: Record<string, string>, handoff?: Partial<AuthorizationHandoff>) => {
  if (!handoff?.state) return invalid('state', 'No authorization in progress')
  // some providers drop state from an error response; a forged success still has to match
  if (parameters.error && !parameters.state) return undefined
  return parameters.state === handoff.state ? undefined : invalid('state', 'Invalid state')
}

// RFC 9207 §2.4: a missing `iss` fails only from a provider that advertised it would send one.
const checkIssuer = (parameters: Record<string, string>, config?: Partial<OpenIdConfig>) => {
  const { issuer, issuerPath, issuerParameter } = (config || {}) as OpenIdConfig
  const expected = (!isTenantTemplate(issuer) && issuer) || issuerPath
  if (!expected) return undefined
  if (!parameters.iss) {
    if (parameters.error || !issuerParameter) return undefined
    return invalid('issuer', 'Missing issuer')
  }
  return sameIssuer(parameters.iss, expected) ? undefined : invalid('issuer', 'Invalid issuer')
}

const checkIdToken = async (token: OAuthToken, handoff: Partial<AuthorizationHandoff> | undefined, verify: IdTokenVerifier) => {
  const claims = await verify(token.id_token)
  if (claims?.error) return invalid('id_token', (claims.error as string) || 'Invalid token')
  if (claims?.nonce !== handoff?.nonce) return invalid('nonce', 'Invalid nonce')
  return { ok: true, token } as const
}

/** Returns the URL to send the user to and the handoff to keep until they return; touches no storage or `location`. */
export const beginAuthorization = async (
  config: Partial<OpenIdConfig> | undefined,
  parameters: AuthorizationCodeParameters,
  { functions }: Pick<AuthorizationOptions, 'functions'> = {}
): Promise<AuthorizationRequest> => resolveOAuthFunctions(functions).authorizationUrl(parameters, config)

/** Checks the redirect's state and issuer, exchanges the code and checks the nonce; `undefined` when it is no callback. */
export const completeAuthorization = async (
  config: Partial<OpenIdConfig> | undefined,
  currentUrl: RedirectSource | undefined,
  handoff?: Partial<AuthorizationHandoff>,
  { functions, verifyIdToken }: AuthorizationOptions = {}
): Promise<AuthorizationResult | undefined> => {
  const { flow, parameters } = parseRedirectParameters(currentUrl)
  if (flow === 'none') return undefined

  const failed = checkState(parameters, handoff) ?? checkIssuer(parameters, config)
  if (failed) return failed
  if (parameters.error) return refused(parameters)

  const verify = verifierFor(config, verifyIdToken)
  if (flow === 'implicit') return checkIdToken({ ...parameters, type: OAuthType.IMPLICIT }, handoff, verify)

  // FR-L2: only the code is believed from the redirect; `code_verifier` and `redirect_uri` come from the handoff.
  const { code_verifier: _verifier, redirect_uri: _redirect, ...answer } = parameters
  const { code_verifier, redirect_uri } = handoff ?? {}
  const exchanged = await resolveOAuthFunctions(functions).authorize(
    { ...answer, ...(redirect_uri && { redirect_uri }), ...(code_verifier && { code_verifier }) },
    config
  )
  if (exchanged?.error) return refused(exchanged)
  // `authorize` hands back what it was given when there was no answer to take its place.
  if (!exchanged?.access_token) return { ok: false, reason: 'unreachable' }
  return checkIdToken(exchanged, handoff, verify)
}
