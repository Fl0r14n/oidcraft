import type { ResolvedConfig } from '../config'
import { CLIENT_SIGNING_ALGS } from '../keys/algorithms'

/**
 * RFC 9728 §3.2: what a resource server publishes so a client can find the provider that issues its
 * tokens. An MCP server must serve this (FR-C6, FR-C19); the core only builds it, since the resource
 * server, not the provider, answers at that URL.
 */
export const protectedResourceMetadata = (config: ResolvedConfig, uri: string) => {
  const resource = config.resources.find(known => known.uri === uri)
  if (!resource) throw new Error(`${uri} is not one of this provider's configured resources`)
  return {
    resource: uri,
    authorization_servers: [config.issuer],
    bearer_methods_supported: ['header'],
    ...(resource.scopes && { scopes_supported: resource.scopes }),
    ...(config.features.dpop && { dpop_signing_alg_values_supported: CLIENT_SIGNING_ALGS })
  }
}

/** RFC 9728 §3.1: the well-known segment goes between the host and the resource's path. */
export const protectedResourceMetadataUrl = (uri: string) => {
  const url = new URL(uri)
  const path = url.pathname === '/' ? '' : url.pathname
  return `${url.origin}/.well-known/oauth-protected-resource${path}`
}
