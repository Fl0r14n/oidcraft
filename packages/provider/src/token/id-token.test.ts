import { describe, expect, test } from 'bun:test'
import { base64url, decodeJwt, decodeProtectedHeader, exportJWK, generateKeyPair } from 'jose'
import { adapter, basic, build, client, ISSUER, tokensFor, useFlow } from '../test-flow'
import { mintIdToken } from './id-token'

useFlow()

describe('ID token details', () => {
  // OIDC Core §3.3.2.11: the hash is the signing algorithm's, so an ES384 token halves a SHA-384.
  test('at_hash uses the hash of the signing algorithm, and the token names its sid', async () => {
    const pair = await generateKeyPair('ES384', { extractable: true })
    const key = { kid: 'es384', alg: 'ES384' }
    const active = adapter.keys.active.bind(adapter.keys)
    adapter.keys.active = async () => [
      {
        ...key,
        privateJwk: { ...(await exportJWK(pair.privateKey)), ...key },
        publicJwk: { ...(await exportJWK(pair.publicKey)), ...key }
      },
      ...(await active())
    ]
    await adapter.clients.upsert?.(client({ idTokenSignedResponseAlg: 'ES384' }))
    const issued = await tokensFor(build())
    const claims = decodeJwt(issued.id_token)
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-384', new TextEncoder().encode(issued.access_token)))
    expect(decodeProtectedHeader(issued.id_token).alg).toBe('ES384')
    expect(claims.at_hash).toBe(base64url.encode(digest.slice(0, 24)))
    expect(claims.sid).toBe((await adapter.sessions.listForAccount('ada'))[0]?.id)
  })

  test('a refresh narrowed to exclude openid returns no ID token', async () => {
    await adapter.clients.upsert?.(client({ scopes: ['openid', 'profile', 'offline_access'] }))
    const provider = build()
    const issued = await tokensFor(provider, 'rp', undefined, { scope: 'openid profile offline_access' })
    const refreshed = await (
      await provider.handle(
        new Request(`${ISSUER}/token`, {
          method: 'POST',
          headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: basic() },
          body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: issued.refresh_token, scope: 'profile' }).toString()
        })
      )
    ).json()
    expect(refreshed.access_token).toBeTruthy()
    expect(refreshed.id_token).toBeUndefined()
  })
})

describe('claims an ID token carries', () => {
  test('cannot restate how the person signed in', async () => {
    const provider = build()
    const session = { id: 's1', accountId: 'ada', authTime: new Date(), clients: [], expiresAt: new Date(Date.now() + 60_000) }
    const token = await mintIdToken(provider.config, {
      client: client(),
      session,
      claims: { name: 'Ada', acr: 'gold', amr: ['hwk'], sub: 'someone-else', nonce: 'forged', at_hash: 'forged' }
    })
    const claims = decodeJwt(token)
    expect(claims).toMatchObject({ name: 'Ada', sub: 'ada' })
    for (const name of ['acr', 'amr', 'nonce', 'at_hash']) expect(claims[name]).toBeUndefined()
  })
})
