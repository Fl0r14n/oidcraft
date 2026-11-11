import type { ResolvedConfig } from '../config'
import { OAuthError } from '../errors'

const refuse = (description: string) => new OAuthError('invalid_target', { description, spec: 'RFC 8707 §2' })

/** The `resource` values a request names, each one this provider was configured to issue tokens for. */
export const requestedResources = (config: ResolvedConfig, params: URLSearchParams) => {
  const named = [...new Set(params.getAll('resource'))]
  for (const resource of named) {
    if (!URL.canParse(resource) || new URL(resource).hash) throw refuse(`resource ${resource} must be an absolute URI without a fragment`)
    if (!config.resources.some(known => known.uri === resource))
      throw refuse(`resource ${resource} is not one this provider issues tokens for`)
  }
  return named
}

/**
 * The one audience a token gets (FR-C19). Naming a resource narrows a token, so a token request may
 * name any configured one when the authorization named none; once it did, only those.
 */
export const audienceFor = (requested: string[], authorized: string[]) => {
  if (requested.length > 1) throw refuse('a token request names at most one resource')
  const [named] = requested
  if (named !== undefined) {
    if (authorized.length && !authorized.includes(named)) throw refuse(`resource ${named} was not part of this authorization`)
    return named
  }
  if (authorized.length > 1) throw refuse('this authorization named several resources; the token request must name one')
  return authorized[0]
}
