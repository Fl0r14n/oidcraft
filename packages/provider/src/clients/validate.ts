import type { Client } from '@oidcraft/adapter'
import type { ResolvedConfig } from '../config'
import { fapiClientProblems } from '../profile/fapi'

/**
 * What must hold of a client however it reaches the store — registration, a metadata document or the
 * management API, on create and on update alike (FR-M1). Each of these is otherwise found at the
 * token endpoint, as a 500 nobody there can fix.
 */
export const clientProblems = (config: ResolvedConfig, client: Client) => {
  const problems: string[] = []

  const unparseable = client.redirectUris.filter(uri => !URL.canParse(uri))
  if (unparseable.length) problems.push(`redirect URI ${unparseable.join(', ')} is not an absolute URL`)

  if (client.requirePkce === false && client.tokenEndpointAuthMethod === 'none') {
    problems.push('a public client cannot opt out of PKCE (FR-C3)')
  }

  if ((client.subjectType ?? config.subjectType) === 'pairwise') {
    if (!config.pairwiseSalt) problems.push('this provider does not issue pairwise subjects: it has no pairwiseSalt (FR-C18)')
    const hosts = new Set(client.redirectUris.filter(uri => URL.canParse(uri)).map(uri => new URL(uri).host))
    if (client.sectorIdentifierUri === undefined && hosts.size > 1) {
      problems.push('redirect_uris span several hosts, so a pairwise client must register a sector_identifier_uri (OIDC Core §8.1)')
    }
  }

  const fapi = fapiClientProblems(config, client)
  if (fapi.length) problems.push(`FAPI 2.0: ${fapi.join('; ')} (FR-C21)`)

  return problems
}
