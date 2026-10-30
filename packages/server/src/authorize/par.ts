import { randomString } from '@oidcraft/core'
import { verifyDpopProof } from '../binding/dpop'
import { authenticateClient } from '../clients/authenticate'
import { publicUrl, type ResolvedConfig } from '../config'
import type { ClientCertificate } from '../context'
import { OAuthError } from '../errors'
import { FAPI_ALGS, FAPI_IAT_SKEW, underFapi } from '../profile/fapi'
import { parseAuthorizationRequest, validateAuthorizationRequest } from './authorization'
import { applyRequestObject } from './request-object'

export const REQUEST_URI_PREFIX = 'urn:ietf:params:oauth:request_uri:'

/** Stores already-validated parameters behind a single-use reference (RFC 9126 §2.2). */
export const pushParameters = async (config: ResolvedConfig, clientId: string, params: URLSearchParams) => {
  const id = randomString()
  await config.adapter.artifacts.upsert({
    id,
    kind: 'pushed_authorization_request',
    clientId,
    payload: { params: params.toString() },
    expiresAt: new Date(Date.now() + config.ttl.pushedAuthorizationRequest * 1000)
  })
  return `${REQUEST_URI_PREFIX}${id}`
}

/**
 * Pushed authorization requests (RFC 9126). The client posts the request over an authenticated
 * back channel and receives a reference, so the parameters never travel through the browser where
 * they can be read, reordered or replaced.
 */
export const pushedAuthorizationRequestEndpoint = async (
  config: ResolvedConfig,
  request: Request,
  certificate?: ClientCertificate | undefined
) => {
  const form = new URLSearchParams(await request.text())
  const { client } = await authenticateClient(config, form, request.headers, certificate)

  // §2.1: a pushed request may not reference another one.
  if (form.has('request_uri')) {
    throw new OAuthError('invalid_request', { description: 'request_uri is not allowed here', spec: 'RFC 9126 §2.1' })
  }

  const params = await applyRequestObject(config, client, form)
  if (params.get('client_id') && params.get('client_id') !== client.clientId) {
    throw new OAuthError('invalid_request', { description: 'client_id does not match the authenticated client', spec: 'RFC 9126 §2.1' })
  }
  params.set('client_id', client.clientId)

  // RFC 9449 §10.1: a proof on the push binds the code to its key, exactly as dpop_jkt would.
  if (config.features.dpop && request.headers.has('dpop')) {
    const { jkt } = await verifyDpopProof(config, request, {
      htu: publicUrl(config, request),
      requireNonceFor: config.features.dpopNonces ? client.clientId : undefined,
      algorithms: underFapi(config, client) ? FAPI_ALGS : undefined,
      futureSkew: underFapi(config, client) ? FAPI_IAT_SKEW : undefined
    })
    if (params.has('dpop_jkt') && params.get('dpop_jkt') !== jkt) {
      throw new OAuthError('invalid_dpop_proof', {
        description: 'dpop_jkt names a different key from the DPoP proof',
        spec: 'RFC 9449 §10.1'
      })
    }
    params.set('dpop_jkt', jkt)
  }

  // Validating now means a malformed request fails on this authenticated call rather than later,
  // in a browser redirect where the user sees it (§2.2).
  const { redirectUri } = await parseAuthorizationRequest(config, params)
  validateAuthorizationRequest(config, client, redirectUri, params)

  const expiresIn = config.ttl.pushedAuthorizationRequest
  return Response.json(
    { request_uri: await pushParameters(config, client.clientId, params), expires_in: expiresIn },
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
  if (!(await config.adapter.artifacts.consume('pushed_authorization_request', id))) {
    throw new OAuthError('invalid_request', { description: 'this request_uri was already used', spec: 'RFC 9126 §4' })
  }
  return new URLSearchParams(artifact.payload.params as string)
}
