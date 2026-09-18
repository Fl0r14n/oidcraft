import { authenticateClient } from '../client-auth'
import type { ResolvedConfig } from '../config'
import { OAuthError } from '../errors'
import { token } from '../random'
import { applyRequestObject } from '../request-object'
import { parseAuthorizationRequest, validateAuthorizationRequest } from './authorization'

export const REQUEST_URI_PREFIX = 'urn:ietf:params:oauth:request_uri:'

/**
 * Pushed authorization requests (RFC 9126). The client posts the request over an authenticated
 * back channel and receives a reference, so the parameters never travel through the browser where
 * they can be read, reordered or replaced.
 */
export const pushedAuthorizationRequestEndpoint = async (config: ResolvedConfig, request: Request) => {
  const form = new URLSearchParams(await request.text())
  const { client } = await authenticateClient(config, form, request.headers)

  // §2.1: a pushed request may not reference another one.
  if (form.has('request_uri')) {
    throw new OAuthError('invalid_request', { description: 'request_uri is not allowed here', spec: 'RFC 9126 §2.1' })
  }

  const params = await applyRequestObject(config, client, form)
  if (params.get('client_id') && params.get('client_id') !== client.clientId) {
    throw new OAuthError('invalid_request', { description: 'client_id does not match the authenticated client', spec: 'RFC 9126 §2.1' })
  }
  params.set('client_id', client.clientId)

  // Validating now means a malformed request fails on this authenticated call rather than later,
  // in a browser redirect where the user sees it (§2.2).
  const { redirectUri } = await parseAuthorizationRequest(config, params)
  validateAuthorizationRequest(config, client, redirectUri, params)

  const id = token()
  const expiresIn = config.ttl.pushedAuthorizationRequest
  await config.adapter.artifacts.upsert({
    id,
    kind: 'pushed_authorization_request',
    clientId: client.clientId,
    payload: { params: params.toString() },
    expiresAt: new Date(Date.now() + expiresIn * 1000)
  })

  return Response.json(
    { request_uri: `${REQUEST_URI_PREFIX}${id}`, expires_in: expiresIn },
    { status: 201, headers: { 'cache-control': 'no-store', pragma: 'no-cache' } }
  )
}

/** Resolves a pushed reference back into the parameters it stands for, single-use (§4). */
export const resolvePushedRequest = async (config: ResolvedConfig, requestUri: string, clientId: string | null) => {
  if (!requestUri.startsWith(REQUEST_URI_PREFIX)) {
    throw new OAuthError('invalid_request', { description: 'this request_uri was not issued here', spec: 'RFC 9126 §4' })
  }
  const id = requestUri.slice(REQUEST_URI_PREFIX.length)
  const artifact = await config.adapter.artifacts.find('pushed_authorization_request', id)
  if (!artifact || artifact.consumedAt) {
    throw new OAuthError('invalid_request', { description: 'this request_uri is unknown, expired, or already used', spec: 'RFC 9126 §4' })
  }
  // The reference travels through the browser, so it must not be usable by another client.
  if (clientId && clientId !== artifact.clientId) {
    throw new OAuthError('invalid_request', { description: 'this request_uri belongs to a different client', spec: 'RFC 9126 §4' })
  }
  await config.adapter.artifacts.consume('pushed_authorization_request', id)
  return new URLSearchParams(artifact.payload.params as string)
}
