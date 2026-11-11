import { beforeEach, describe, expect, test } from 'bun:test'
import { randomString, sha256 } from '@oidcraft/core'
import { base64url } from 'jose'
import { memoryAdapter } from '../adapters/memory'
import type { Adapter } from '../index'
import { createProvider, type Provider } from '../provider'
import { SESSION_COOKIE } from '../session/session'

const ISSUER = 'https://op.example.com'
const CLIENT_ID = 'https://app.example.com/oauth/client-metadata.json'
const REDIRECT = 'http://localhost:3000/callback'

// MCP 2026-07-28's own example document.
const document = (over: Record<string, unknown> = {}) => ({
  client_id: CLIENT_ID,
  client_name: 'Example MCP Client',
  client_uri: 'https://app.example.com',
  redirect_uris: ['http://127.0.0.1:3000/callback', REDIRECT],
  grant_types: ['authorization_code'],
  response_types: ['code'],
  token_endpoint_auth_method: 'none',
  ...over
})

const accounts = {
  async find(accountId: string) {
    return { accountId, claims: {} }
  },
  async claims() {
    return {}
  }
}

let adapter: Adapter
let provider: Provider
let served: Record<string, unknown> | undefined
let fetched: string[]
let verifier: string
let challenge: string

beforeEach(async () => {
  adapter = await memoryAdapter({ accounts })
  served = document()
  fetched = []
  provider = createProvider({
    issuer: ISSUER,
    adapter,
    interactionUrl: `${ISSUER}/interaction`,
    resolveClientMetadata: async clientId => {
      fetched.push(clientId)
      return clientId === CLIENT_ID ? served : undefined
    }
  })
  verifier = randomString() + randomString()
  challenge = base64url.encode(await sha256(verifier))
})

const authorize = (clientId = CLIENT_ID, redirectUri = REDIRECT) =>
  provider.handle(
    new Request(
      `${ISSUER}/authorize?${new URLSearchParams({
        client_id: clientId,
        redirect_uri: redirectUri,
        response_type: 'code',
        scope: 'openid',
        state: 's',
        code_challenge: challenge,
        code_challenge_method: 'S256'
      })}`
    )
  )

describe('client ID metadata documents (FR-C20)', () => {
  test('discovery advertises them only when the host can resolve them', async () => {
    const metadata = async (p: Provider) => (await p.handle(new Request(`${ISSUER}/.well-known/oauth-authorization-server`))).json()
    expect((await metadata(provider)).client_id_metadata_document_supported).toBe(true)
    const without = createProvider({ issuer: ISSUER, adapter, interactionUrl: `${ISSUER}/interaction` })
    expect((await metadata(without)).client_id_metadata_document_supported).toBeUndefined()
  })

  test('a document-registered client signs a person in, end to end, with no registration step', async () => {
    const first = await authorize()
    const loginId = new URL(first.headers.get('location') as string).pathname.split('/').pop() as string
    const login = await provider.interactions.complete(loginId, { login: { accountId: 'ada' } })
    const cookie = `${SESSION_COOKIE}=${(login.setCookie as string).split('=')[1]?.split(';')[0]}`
    const second = await provider.handle(new Request(login.redirectTo, { headers: { cookie } }))
    const consentId = new URL(second.headers.get('location') as string).pathname.split('/').pop() as string

    // What the consent screen needs to name a client that could call itself anything.
    const view = await provider.interactions.find(consentId)
    expect(view.clientId).toBe(CLIENT_ID)
    expect(view.redirectUri).toBe(REDIRECT)

    const consent = await provider.interactions.complete(consentId, { consent: { scopes: ['openid'] } })
    const third = await provider.handle(new Request(consent.redirectTo, { headers: { cookie } }))
    const code = new URL(third.headers.get('location') as string).searchParams.get('code') as string

    const token = await provider.handle(
      new Request(`${ISSUER}/token`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          redirect_uri: REDIRECT,
          client_id: CLIENT_ID,
          code_verifier: verifier
        })
      })
    )
    expect(token.status).toBe(200)
    expect((await token.json()).id_token).toBeTruthy()
  })

  test('a redirect_uri the document does not list is refused, never redirected to', async () => {
    const response = await authorize(CLIENT_ID, 'https://evil.example.net/cb')
    expect(response.status).toBe(400)
    expect(response.headers.get('location')).toBeNull()
  })

  const refusedWith = async (over: Record<string, unknown>) => {
    served = document(over)
    const response = await authorize()
    expect(response.headers.get('location')).toBeNull()
    return ((await response.json()) as { error_description: string }).error_description
  }

  test('a document naming another client_id is refused', async () => {
    expect(await refusedWith({ client_id: 'https://other.example.com/client.json' })).toContain('different client_id')
  })

  test('a document cannot hold a shared secret, or ask to authenticate with one', async () => {
    expect(await refusedWith({ client_secret: 's3cret' })).toContain('shared secret')
    expect(await refusedWith({ token_endpoint_auth_method: 'client_secret_basic' })).toContain('shared secret')
  })

  test('private_key_jwt needs keys to verify with', async () => {
    expect(await refusedWith({ token_endpoint_auth_method: 'private_key_jwt' })).toContain('jwks')
  })

  test('only the code and refresh grants', async () => {
    expect(await refusedWith({ grant_types: ['client_credentials'] })).toContain('not available')
  })

  test('a web application may not return to http://localhost', async () => {
    expect((await refusedWith({ application_type: 'web' })).toLowerCase()).toContain('https')
  })

  // Fetched on a stranger's say-so, so these never reach the host's resolver at all (SSRF).
  test('a client_id that is not a canonical https URL with a path is refused before anything is fetched', async () => {
    for (const clientId of [
      'https://app.example.com',
      'https://app.example.com/',
      'https://app.example.com/a/../client.json',
      'https://app.example.com/client.json?x=1',
      'https://user:pass@app.example.com/client.json',
      'https://APP.example.com/client.json',
      'https://127.0.0.1/client.json',
      'https://localhost/client.json'
    ]) {
      const response = await authorize(clientId)
      expect({ clientId, status: response.status }).toEqual({ clientId, status: 400 })
    }
    expect(fetched).toEqual([])
  })

  test('a document the host will not resolve leaves the client unknown', async () => {
    const response = await authorize('https://unknown.example.com/client.json')
    expect(response.status).toBe(400)
    expect(fetched).toEqual(['https://unknown.example.com/client.json'])
  })

  test('a stored client with a URL id is used as stored, and nothing is fetched', async () => {
    await adapter.clients.upsert?.({
      clientId: CLIENT_ID,
      redirectUris: ['https://app.example.com/cb'],
      grantTypes: ['authorization_code'],
      responseTypes: ['code'],
      scopes: ['openid'],
      tokenEndpointAuthMethod: 'none',
      createdAt: new Date(),
      updatedAt: new Date()
    })
    expect((await authorize(CLIENT_ID, 'https://app.example.com/cb')).status).toBe(303)
    expect(fetched).toEqual([])
  })
})
