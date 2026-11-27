import { describe, expect, test } from 'bun:test'
import { basic, ISSUER, provider, useFlow } from './test-flow'

useFlow()

const token = (body: string, headers: Record<string, string>) =>
  provider.handle(new Request(`${ISSUER}/token`, { method: 'POST', headers: { authorization: basic(), ...headers }, body }))

// RFC 6749 Appendix B: every endpoint that takes a body takes it form-encoded.
describe('a request body', () => {
  test('in another media type is refused as one, not parsed as a form', async () => {
    const response = await token(JSON.stringify({ grant_type: 'client_credentials' }), { 'content-type': 'application/json' })
    expect(response.status).toBe(415)
    expect((await response.json()).error).toBe('invalid_request')
  })

  test('without a media type is refused', async () => {
    const response = await provider.handle(
      new Request(`${ISSUER}/token`, { method: 'POST', headers: { authorization: basic() }, body: new Blob(['grant_type=x']) })
    )
    expect(response.status).toBe(415)
  })

  test('form-encoded with a charset is read', async () => {
    const response = await token('grant_type=authorization_code&code=x', {
      'content-type': 'Application/X-WWW-Form-Urlencoded; charset=UTF-8'
    })
    expect((await response.json()).error).toBe('invalid_grant')
  })

  test('an empty POST needs no media type: UserInfo by header alone', async () => {
    const response = await provider.handle(
      new Request(`${ISSUER}/userinfo`, { method: 'POST', headers: { authorization: 'Bearer unknown' } })
    )
    expect(response.status).toBe(401)
  })
})

// Past the cap the body is refused unread, however it arrives; a tighter limit is the host's (NFR-S12).
describe('a request body over 1 MiB', () => {
  const form = { 'content-type': 'application/x-www-form-urlencoded' }
  const big = `grant_type=client_credentials&padding=${'x'.repeat(1 << 20)}`

  test('is 413 by its declared length or as it streams in', async () => {
    expect((await token(big, form)).status).toBe(413)
    const streamed = new ReadableStream<Uint8Array>({
      start(controller) {
        for (let i = 0; i < 20; i++) controller.enqueue(new TextEncoder().encode('x'.repeat(64 * 1024)))
        controller.close()
      }
    })
    const response = await provider.handle(
      new Request(`${ISSUER}/token`, {
        method: 'POST',
        headers: { authorization: basic(), ...form },
        body: streamed,
        duplex: 'half'
      } as RequestInit)
    )
    expect(response.status).toBe(413)
  })

  test('one under it is read as before', async () => {
    const response = await token(`grant_type=authorization_code&code=x&padding=${'x'.repeat(900_000)}`, form)
    expect(response.status).toBe(400)
    expect((await response.json()).error).toBe('invalid_grant')
  })
})
