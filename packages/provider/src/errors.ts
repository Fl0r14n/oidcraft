/** The OAuth error codes this provider can emit. RFC 6749 §4.1.2.1 and §5.2, OIDC Core §3.1.2.6. */
export type OAuthErrorCode =
  | 'invalid_request'
  | 'invalid_client'
  | 'invalid_grant'
  | 'invalid_scope'
  | 'unauthorized_client'
  | 'unsupported_grant_type'
  | 'unsupported_response_type'
  | 'access_denied'
  | 'server_error'
  | 'temporarily_unavailable'
  | 'interaction_required'
  | 'login_required'
  | 'consent_required'
  | 'account_selection_required'
  | 'invalid_target'
  | 'invalid_dpop_proof'
  | 'use_dpop_nonce'
  | 'authorization_pending'
  | 'slow_down'
  | 'expired_token'
  | 'invalid_authorization_details'
  | 'unknown_user_id'

export type OAuthErrorInit = {
  description?: string
  /** The clause the caller violated, so the message says where to look. */
  spec?: string
  status?: number
  headers?: Record<string, string>
  cause?: unknown
}

export class OAuthError extends Error {
  readonly code: OAuthErrorCode
  readonly description: string | undefined
  readonly spec: string | undefined
  readonly status: number
  readonly headers: Record<string, string>

  constructor(code: OAuthErrorCode, init: OAuthErrorInit = {}) {
    super(init.spec ? `${code}: ${init.description ?? ''} (${init.spec})` : `${code}: ${init.description ?? ''}`)
    this.name = 'OAuthError'
    this.code = code
    this.description = init.description
    this.spec = init.spec
    this.status = init.status ?? STATUS[code]
    this.headers = init.headers ?? {}
    if (init.cause !== undefined) this.cause = init.cause
  }

  get body() {
    const uri = this.spec && specUri(this.spec)
    return {
      error: this.code,
      ...(this.description && { error_description: this.description.replace(OUTSIDE_ERROR_TEXT, '?') }),
      ...(uri && { error_uri: uri })
    }
  }
}

// RFC 6749 §5.2: error_description is printable ASCII without `"` or `\`, and it carries client-supplied values.
const OUTSIDE_ERROR_TEXT = /[^\x20\x21\x23-\x5B\x5D-\x7E]/g

/** RFC 6749 §5.2: error_uri must be a URI, so a citation becomes one only when it names an RFC. */
const specUri = (spec: string) => {
  const cited = /RFC (\d{4})(?: §([\d.]+))?/.exec(spec)
  if (!cited) return undefined
  return `https://www.rfc-editor.org/rfc/rfc${cited[1]}${cited[2] ? `#section-${cited[2].replace(/\.$/, '')}` : ''}`
}

const STATUS: Record<OAuthErrorCode, number> = {
  invalid_request: 400,
  invalid_client: 401,
  invalid_grant: 400,
  invalid_scope: 400,
  unauthorized_client: 400,
  unsupported_grant_type: 400,
  unsupported_response_type: 400,
  access_denied: 403,
  server_error: 500,
  temporarily_unavailable: 503,
  interaction_required: 400,
  login_required: 400,
  consent_required: 400,
  account_selection_required: 400,
  invalid_target: 400,
  invalid_dpop_proof: 400,
  use_dpop_nonce: 400,
  // RFC 8628 §3.5: these are the normal course of a device flow, not failures of the request.
  authorization_pending: 400,
  slow_down: 400,
  expired_token: 400,
  invalid_authorization_details: 400,
  unknown_user_id: 400
}

/**
 * A misconfiguration, raised while building the provider rather than on the first request (NFR-D2).
 * Separate from OAuthError because it is never a response: nobody is waiting for it.
 */
export class ConfigurationError extends Error {
  readonly problems: string[]

  constructor(problems: string[]) {
    super(`the provider configuration is not usable:\n${problems.map(p => `  - ${p}`).join('\n')}`)
    this.name = 'ConfigurationError'
    this.problems = problems
  }
}

const NO_STORE = { 'cache-control': 'no-store', pragma: 'no-cache' }

export const errorResponse = (error: unknown) => {
  const oauth = error instanceof OAuthError ? error : new OAuthError('server_error', { description: 'unexpected failure', cause: error })
  return Response.json(oauth.body, {
    status: oauth.status,
    headers: { ...NO_STORE, ...oauth.headers }
  })
}
