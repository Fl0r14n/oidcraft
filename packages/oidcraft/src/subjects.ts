import type { ResolvedConfig } from './config'
import { base64url, sha256 } from './random'
import type { Client } from './types'

/**
 * The sector a pairwise subject is scoped to (OIDC Core §8.1).
 *
 * `sector_identifier_uri` lets several clients share one pairwise subject deliberately. Without it
 * the host of the registered redirect URIs is the sector — which is why a client with redirect URIs
 * across several hosts must declare one, or the subject it gets would depend on which URI was used.
 */
export const sectorOf = (client: Client) => {
  if (client.sectorIdentifierUri) return new URL(client.sectorIdentifierUri).host
  const hosts = new Set(client.redirectUris.map(uri => new URL(uri).host))
  if (hosts.size === 1) return [...hosts][0] as string
  throw new Error(
    `client ${client.clientId} has redirect URIs on ${hosts.size} hosts and no sector_identifier_uri, ` +
      'so a pairwise subject would depend on which one was used (OIDC Core §8.1)'
  )
}

/**
 * A subject that is stable for this client and useless to any other (FR-C18).
 *
 * The salt is what stops a colluding pair of relying parties from correlating users: without it the
 * mapping is a pure function of the account and sector, which anyone can recompute.
 */
export const pairwiseSubject = async (accountId: string, sector: string, salt: string) =>
  base64url(await sha256(`${sector}.${accountId}.${salt}`))

export const subjectFor = async (config: ResolvedConfig, client: Client, accountId: string) => {
  if ((client.subjectType ?? config.subjectType) !== 'pairwise') return accountId
  if (!config.pairwiseSalt) {
    throw new Error('pairwiseSalt is required to issue pairwise subjects; without one they are trivially correlated (FR-C18)')
  }
  return pairwiseSubject(accountId, sectorOf(client), config.pairwiseSalt)
}
