import type { Client } from '@oidcraft/adapter'
import { canonicalIp, registeredNames } from '../binding/mtls'
import type { ResolvedConfig } from '../config'
import { fapiClientProblems } from '../profile/fapi'
import { secretKind } from './secret'

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

  const secret = secretKind(client.tokenEndpointAuthMethod)
  if (secret === 'hashed' && !client.clientSecretHash) problems.push(`${client.tokenEndpointAuthMethod} needs a client secret`)
  if (secret === 'hashed' && client.clientSecret) problems.push('a client secret is stored only as its hash (NFR-S11)')
  if (secret === 'key' && !client.clientSecret)
    problems.push('client_secret_jwt needs its client secret, which a stored hash cannot give back')

  if (client.tokenEndpointAuthMethod === 'tls_client_auth') {
    const names = registeredNames(client)
    if (names.length !== 1) {
      problems.push(
        'tls_client_auth needs exactly one of tls_client_auth_subject_dn, _san_dns, _san_uri, _san_ip and _san_email (RFC 8705 §2.1.2)'
      )
    } else if (names[0] !== 'tlsClientAuthSubjectDn' && !config.capabilities.clientCertificateSans) {
      problems.push('this runtime supplies no certificate SANs, so a tls_client_auth client must register its subject DN (FR-R5)')
    }
  }
  if (client.tlsClientAuthSanIp !== undefined && canonicalIp(client.tlsClientAuthSanIp) === undefined) {
    problems.push(`tls_client_auth_san_ip ${client.tlsClientAuthSanIp} is not an IP address`)
  }
  if (client.tlsClientAuthSanEmail !== undefined && !client.tlsClientAuthSanEmail.includes('@')) {
    problems.push(`tls_client_auth_san_email ${client.tlsClientAuthSanEmail} is not an email address`)
  }

  const fapi = fapiClientProblems(config, client)
  if (fapi.length) problems.push(`FAPI 2.0: ${fapi.join('; ')} (FR-C21)`)

  return problems
}
