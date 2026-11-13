import type { Client } from '@oidcraft/adapter'
import { base64url } from 'jose'
import type { ResolvedConfig } from '../config'

// OIDC Core §8.1: redirect URIs on several hosts need a `sector_identifier_uri`, or the subject would depend on the URI used.
export const sectorOf = (client: Client) => {
  if (client.sectorIdentifierUri) return new URL(client.sectorIdentifierUri).host
  const hosts = new Set(client.redirectUris.map(uri => new URL(uri).host))
  if (hosts.size === 1) return [...hosts][0] as string
  throw new Error(
    `client ${client.clientId} has redirect URIs on ${hosts.size} hosts and no sector_identifier_uri, ` +
      'so a pairwise subject would depend on which one was used (OIDC Core §8.1)'
  )
}

// FR-C18: the salt stops colluding relying parties recomputing the mapping from account and sector.
export const pairwiseSubject = async (accountId: string, sector: string, salt: string) => {
  const encoder = new TextEncoder()
  const key = await crypto.subtle.importKey('raw', encoder.encode(salt), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  // A JSON pair, not a joined string: a dot can then not move between the sector and the account.
  return base64url.encode(new Uint8Array(await crypto.subtle.sign('HMAC', key, encoder.encode(JSON.stringify([sector, accountId])))))
}

export const subjectFor = async (config: ResolvedConfig, client: Client, accountId: string) => {
  if ((client.subjectType ?? config.subjectType) !== 'pairwise') return accountId
  if (!config.pairwiseSalt) {
    throw new Error('pairwiseSalt is required to issue pairwise subjects; without one they are trivially correlated (FR-C18)')
  }
  return pairwiseSubject(accountId, sectorOf(client), config.pairwiseSalt)
}
