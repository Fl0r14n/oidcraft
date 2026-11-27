import type { Client } from '@oidcraft/adapter'
import { constantTimeEquals, randomString } from '@oidcraft/core'
import { storedId } from '../artifacts'
import { audit } from '../audit'
import type { ResolvedConfig } from '../config'
import { OAuthError } from '../errors'
import { readJson } from '../form'
import { guarded } from '../hooks'
import { signingAlgorithms } from '../keys/keys'
import { defaultSigningAlg } from '../profile/fapi'
import { deleteClient } from './delete'
import { clientResponse, invalid, metadataFrom, objectFrom, TLS_CLIENT_AUTH_METADATA } from './metadata'
import { secretKind, storableSecret } from './secret'
import { serverUri } from './uris'
import { clientProblems } from './validate'

/** FR-T1: `none` never, and never an algorithm the provider holds no key for. */
const assertSignable = async (config: ResolvedConfig, client: Client) => {
  const alg = client.idTokenSignedResponseAlg
  if (!alg) return
  if (!signingAlgorithms(await config.adapter.keys.list()).includes(alg)) {
    throw invalid(`id_token_signed_response_alg ${alg} is not one this provider signs with`)
  }
}

/** OIDC DCR 1.0 §5: every registered redirect_uri must be listed, or registration fails (FR-C18). */
const assertSector = async (config: ResolvedConfig, client: Client) => {
  const uri = client.sectorIdentifierUri
  if (uri === undefined) return
  serverUri(uri, 'sector_identifier_uri')
  if (!config.resolveSectorIdentifier) throw invalid('this provider cannot validate a sector_identifier_uri')
  // One answer for a fetch that failed and one that found no list, so it tells a prober nothing about the network (NFR-S14).
  const unreadable = () => invalid(`sector_identifier_uri ${uri} did not answer with a JSON array of redirect URIs`)
  const listed = await config.resolveSectorIdentifier(uri).catch(() => {
    throw unreadable()
  })
  if (!Array.isArray(listed)) throw unreadable()
  const missing = client.redirectUris.filter(each => !listed.includes(each))
  if (missing.length) throw invalid(`sector_identifier_uri does not list ${missing.join(', ')}`)
}

const assertRegistrable = async (config: ResolvedConfig, client: Client) => {
  await assertSignable(config, client)
  await assertSector(config, client)
  const problems = clientProblems(config, client)
  if (problems.length) throw invalid(problems.join('; '))
}

// What an update replaces or, left out, removes (RFC 7592 §2.2); the rest of a stored client is the operator's (FR-C9, FR-C21).
const REGISTERED = new Set<string>([
  ...['clientName', 'applicationType', 'redirectUris', 'postLogoutRedirectUris', 'grantTypes', 'responseTypes', 'scopes'],
  ...['tokenEndpointAuthMethod', 'clientSecret', 'clientSecretHash', 'sectorIdentifierUri', 'subjectType', 'requirePkce'],
  ...['backchannelTokenDeliveryMode', 'backchannelClientNotificationEndpoint', 'idTokenSignedResponseAlg', 'jwks', 'jwksUri'],
  ...['defaultAcrValues'],
  ...['backchannelLogoutUri', ...Object.values(TLS_CLIENT_AUTH_METADATA)]
])

const operatorFields = (client: Client) => Object.fromEntries(Object.entries(client).filter(([name]) => !REGISTERED.has(name)))

// FR-C9: what was vouched for a client authenticating one way is not vouched for another; its restrictions stay.
const operatorFieldsAfter = (client: Client, method: Client['tokenEndpointAuthMethod']) => {
  const { resourceServer: _vouched, ...restrictions } = operatorFields(client)
  return method === client.tokenEndpointAuthMethod ? operatorFields(client) : restrictions
}

const authorizeRegistrationAccess = async (config: ResolvedConfig, request: Request, clientId: string | null) => {
  if (!clientId) throw new OAuthError('invalid_request', { description: 'client_id is required', status: 400, spec: 'RFC 7592 §2' })
  const header = request.headers.get('authorization')
  const presented = header?.toLowerCase().startsWith('bearer ') ? header.slice(7).trim() : undefined
  const client = await config.adapter.clients.find(clientId)
  // An unknown client and a wrong token are the same answer: otherwise this enumerates client ids.
  const matches = Boolean(
    client?.registrationAccessToken && presented && (await constantTimeEquals(await storedId(presented), client.registrationAccessToken))
  )
  if (!client || !presented || !matches) {
    throw new OAuthError('invalid_client', {
      description: 'no registration access token for this client',
      spec: 'RFC 7592 §2',
      status: 401,
      headers: { 'www-authenticate': 'Bearer' }
    })
  }
  return { client, presented }
}

/** FR-C3: only the host's registrationPolicy can exempt a dynamically registered client, and never a public one. */
const applyDecision = (client: Client, decision: { requirePkce?: boolean } | undefined) => {
  if (decision?.requirePkce !== false) return
  if (client.tokenEndpointAuthMethod === 'none') throw invalid('a public client cannot be exempted from PKCE')
  client.requirePkce = false
}

/** Under FAPI 2.0 the response names the algorithm it will sign with: to a DCR client an omitted one means RS256. */
const settleIdTokenAlg = async (config: ResolvedConfig, client: Client) => {
  if (client.idTokenSignedResponseAlg) return
  const alg = defaultSigningAlg(config, client, await config.adapter.keys.list())
  if (alg) client.idTokenSignedResponseAlg = alg
}

/** OIDC Dynamic Client Registration 1.0 and RFC 7592. Off unless a deployment turns it on (FR-C9). */
export const registrationEndpoint = async (config: ResolvedConfig, request: Request) => {
  const url = new URL(request.url)

  if (request.method === 'POST') {
    const decision = config.registrationPolicy ? await config.registrationPolicy(request.clone(), { existing: undefined }) : undefined
    const parsed = await readJson(request)
    if (parsed === undefined) throw invalid('the registration request must be JSON')
    const body = objectFrom(parsed, 'the registration request')

    const { client, issued } = await storableSecret(metadataFrom(config, body), true)
    await settleIdTokenAlg(config, client)
    await assertRegistrable(config, client)
    applyDecision(client, decision)
    if (!config.adapter.clients.upsert) throw new OAuthError('server_error', { description: 'this adapter cannot create clients' })
    const registrationAccessToken = randomString()
    await config.adapter.clients.upsert({ ...client, registrationAccessToken: await storedId(registrationAccessToken) })
    await guarded(config, request, () => audit(config, 'client.register', { clientId: client.clientId }))
    return Response.json(clientResponse(config, client, registrationAccessToken, issued), {
      status: 201,
      headers: { 'cache-control': 'no-store' }
    })
  }

  const { client, presented } = await authorizeRegistrationAccess(config, request, url.searchParams.get('client_id'))

  if (request.method === 'GET') {
    return Response.json(clientResponse(config, client, presented), { headers: { 'cache-control': 'no-store' } })
  }

  if (request.method === 'DELETE') {
    await deleteClient(config, client.clientId)
    await guarded(config, request, () => audit(config, 'client.delete', { clientId: client.clientId }))
    return new Response(null, { status: 204, headers: { 'cache-control': 'no-store' } })
  }

  // The host vets an update as it vetted the first registration; its answer, not the stored client, decides PKCE (FR-C3).
  const decision = config.registrationPolicy ? await config.registrationPolicy(request.clone(), { existing: client }) : undefined
  const parsed = await readJson(request)
  if (parsed === undefined) throw invalid('the update must be JSON')
  const body = objectFrom(parsed, 'the update')
  const metadata = metadataFrom(config, body, client)
  // A secret survives a method change only where it is kept the same way; otherwise a new one is issued.
  const sameSecret = secretKind(metadata.tokenEndpointAuthMethod) === secretKind(client.tokenEndpointAuthMethod)
  // Identity and the token that grants access to it are the server's, not the client's to change.
  const { client: updated, issued } = await storableSecret(
    {
      ...operatorFieldsAfter(client, metadata.tokenEndpointAuthMethod),
      ...metadata,
      clientId: client.clientId,
      ...(sameSecret && client.clientSecret && { clientSecret: client.clientSecret }),
      ...(sameSecret && client.clientSecretHash && { clientSecretHash: client.clientSecretHash }),
      registrationAccessToken: client.registrationAccessToken as string,
      createdAt: client.createdAt,
      updatedAt: Date.now()
    },
    true
  )
  await settleIdTokenAlg(config, updated)
  await assertRegistrable(config, updated)
  applyDecision(updated, decision)
  if (!config.adapter.clients.upsert) throw new OAuthError('server_error', { description: 'this adapter cannot update clients' })
  await config.adapter.clients.upsert(updated)
  await guarded(config, request, () => audit(config, 'client.update', { clientId: client.clientId }))
  return Response.json(clientResponse(config, updated, presented, issued), { headers: { 'cache-control': 'no-store' } })
}
