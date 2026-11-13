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

/**
 * How a callback ended, told apart without reading message text (FR-L2): `refused` when the provider
 * said no, at the redirect or the token endpoint; `invalid` when a check here failed; `unreachable`
 * when the token endpoint did not answer.
 */
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

/** RFC 6749 §10.12. Only checked against a state we hold, so a callback arriving without a prior
 * `beginAuthorization` — a deep link, a resumed session — is left to the caller as before. */
const checkState = (parameters: Record<string, string>, handoff?: Partial<AuthorizationHandoff>) => {
  if (!handoff?.state) return undefined
  // some providers drop state from the error response; the error is more useful than a state complaint,
  // and a forged *success* still has to match
  if (parameters.error && !parameters.state) return undefined
  return parameters.state === handoff.state ? undefined : invalid('state', 'Invalid state')
}

/**
 * RFC 9207 §2.4. `iss` says which authorization server actually answered, and checking it is what
 * stops a mix-up attack: with more than one provider configured, a code minted by an attacker's AS
 * is otherwise indistinguishable from one minted by the honest one, and gets exchanged there.
 *
 * A provider that advertises `authorization_response_iss_parameter_supported` has promised to send
 * it, so from that provider a missing `iss` is as much a failure as a wrong one. From a provider
 * that never promised, absence is just absence.
 */
const checkIssuer = (parameters: Record<string, string>, config?: Partial<OpenIdConfig>) => {
  const { issuer, issuerPath, issuerParameter } = (config || {}) as OpenIdConfig
  const expected = (!isTenantTemplate(issuer) && issuer) || issuerPath
  if (!expected) return undefined
  if (!parameters.iss) {
    // as with state: on an error response the error itself is the more useful answer
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

/** Starts an authorization request without performing it: returns the URL to send the user to and the
 * handoff to keep until they come back. Nothing here touches storage, `location` or a Vue ref, so it is
 * as usable from a request handler as from a browser. */
export const beginAuthorization = async (
  config: Partial<OpenIdConfig> | undefined,
  parameters: AuthorizationCodeParameters,
  { functions }: Pick<AuthorizationOptions, 'functions'> = {}
): Promise<AuthorizationRequest> => resolveOAuthFunctions(functions).authorizationUrl(parameters, config)

/** Finishes one: classifies the redirect, checks state, exchanges the code and checks the nonce. The
 * handoff is passed back in rather than looked up, which is what makes it safe to run concurrently. */
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

  // the handoff carries redirect_uri and code_verifier, the redirect carries the code — the token
  // endpoint needs both, and the type is set by `authorize`, so it stays unset here
  const exchanged = await resolveOAuthFunctions(functions).authorize({ ...handoff, ...parameters }, config)
  if (exchanged?.error) return refused(exchanged)
  // `authorize` hands back what it was given when there was no answer to take its place.
  if (!exchanged?.access_token) return { ok: false, reason: 'unreachable' }
  return checkIdToken(exchanged, handoff, verify)
}
