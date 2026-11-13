import { describe, expect, test } from 'bun:test'
import { adapter, build, challenge, client, ISSUER, REDIRECT, useFlow } from '../test-flow'
import { SESSION_COOKIE } from './session'

useFlow()

describe('malformed cookies are client errors, not 500s', () => {
  test('a cookie that is not percent-decodable is ignored', async () => {
    await adapter.clients.upsert?.(client())
    const params = new URLSearchParams({
      client_id: 'rp',
      redirect_uri: REDIRECT,
      response_type: 'code',
      scope: 'openid',
      code_challenge: challenge,
      code_challenge_method: 'S256'
    })
    const response = await build().handle(
      new Request(`${ISSUER}/authorize?${params}`, { headers: { cookie: `${SESSION_COOKIE}=%E0%A4%A; other=1` } })
    )
    expect(response.status).toBe(303)
  })
})
