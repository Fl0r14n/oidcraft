import type { Client } from '@oidcraft/adapter'
import { createLocalJWKSet, type JSONWebKeySet } from 'jose'
import type { ResolvedConfig } from '../config'
import type { OAuthError } from '../errors'

// The host resolves `jwks_uri`: fetching it here would be outbound I/O to a URL the client chose (FR-A1).
export const clientKeySet = async (
  config: ResolvedConfig,
  client: Client,
  refuse: (description: string, spec?: string) => OAuthError,
  purpose: string
) => {
  if (client.jwks) return createLocalJWKSet(client.jwks as unknown as JSONWebKeySet)
  if (client.jwksUri) {
    if (!config.resolveClientJwks) {
      throw refuse(
        `client ${client.clientId} registered a jwks_uri but no resolveClientJwks was configured; the core does not fetch it itself`,
        'ARCHITECTURE.md §3.2'
      )
    }
    return createLocalJWKSet((await config.resolveClientJwks(client)) as unknown as JSONWebKeySet)
  }
  throw refuse(`client ${client.clientId} has no keys registered, so it cannot ${purpose}`)
}
