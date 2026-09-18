import { beforeEach, describe, expect, it } from 'bun:test'
import type { OAuth } from './module'
import { createOAuth, installStorage, mockOAuthFunctions, registerOAuthCleanup } from './test-utils'

const local = installStorage()
registerOAuthCleanup()

/** A real local server, so the assertions are about what was sent rather than about a mock's arguments. */
let server: ReturnType<typeof Bun.serve>
let seen: Array<{ url: string; authorization: string | null; contentType: string | null; accept: string | null }>
let respond: () => Response

const origin = () => `http://localhost:${server.port}`

describe('authorized transport', () => {
  let oauth: OAuth
  let refresh: ReturnType<typeof mockOAuthFunctions>['refresh']

  beforeEach(() => {
    local.clear()
    seen = []
    respond = () => Response.json({ ok: true })
    server ??= Bun.serve({
      port: 0,
      fetch: request => {
        seen.push({
          url: new URL(request.url).pathname,
          authorization: request.headers.get('authorization'),
          contentType: request.headers.get('content-type'),
          accept: request.headers.get('accept')
        })
        return respond()
      }
    })
    const functions = mockOAuthFunctions()
    refresh = functions.refresh
    oauth = createOAuth({ ignorePaths: [/public/], functions })
  })

  describe('authHeaders', () => {
    it('returns the bearer', async () => {
      oauth.setToken({ access_token: 'at', token_type: 'Bearer' })

      expect(await oauth.authHeaders('/api/orders')).toEqual({ Authorization: 'Bearer at' })
    })

    it('refreshes an expired token before answering', async () => {
      refresh.mockResolvedValue({ access_token: 'fresh', token_type: 'Bearer', expires_in: 60 })
      oauth.setConfig({ tokenPath: '/t', clientId: 'c' })
      oauth.setToken({ access_token: 'stale', token_type: 'Bearer', refresh_token: 'r', expires: Date.now() - 10_000 })

      expect(await oauth.authHeaders('/api/orders')).toEqual({ Authorization: 'Bearer fresh' })
      expect(refresh).toHaveBeenCalled()
    })

    it('is empty for an ignored path', async () => {
      oauth.setToken({ access_token: 'at', token_type: 'Bearer' })

      expect(await oauth.authHeaders('/api/public/products')).toEqual({})
    })

    it('is empty without a token', async () => {
      expect(await oauth.authHeaders('/api/orders')).toEqual({})
    })
  })

  describe('oauth.fetch', () => {
    it('sends the bearer', async () => {
      oauth.setToken({ access_token: 'at', token_type: 'Bearer' })

      await oauth.fetch(`${origin()}/api/orders`)

      expect(seen[0]?.url).toBe('/api/orders')
      expect(seen[0]?.authorization).toBe('Bearer at')
    })

    it('does not send it to an ignored path', async () => {
      oauth.setToken({ access_token: 'at', token_type: 'Bearer' })

      await oauth.fetch(`${origin()}/api/public/products`)

      expect(seen[0]?.authorization).toBeNull()
    })

    it('defaults Content-Type to JSON for a string body', async () => {
      // the platform would label this text/plain, which a strict API answers 415 to
      await oauth.fetch(`${origin()}/api/orders`, { method: 'POST', body: '{}' })

      expect(seen[0]?.contentType).toBe('application/json')
    })

    it('sends no Content-Type on a bodyless request', async () => {
      // the header describes a body that is not there, and a strict gateway may reject it
      await oauth.fetch(`${origin()}/api/orders`)

      expect(seen[0]?.contentType).toBeNull()
    })

    it('defaults Accept to JSON, body or not', async () => {
      // Accept is what actually asks for JSON back — Content-Type never did
      await oauth.fetch(`${origin()}/api/orders`)

      expect(seen[0]?.accept).toBe('application/json')
    })

    it('does not override an Accept the caller set', async () => {
      await oauth.fetch(`${origin()}/api/report.pdf`, { headers: { Accept: 'application/pdf' } })

      expect(seen[0]?.accept).toBe('application/pdf')
    })

    it('does not override a Content-Type the caller set', async () => {
      await oauth.fetch(`${origin()}/api/orders`, { method: 'POST', headers: { 'Content-Type': 'text/csv' }, body: 'a,b' })

      expect(seen[0]?.contentType).toBe('text/csv')
    })

    it('leaves a FormData body to type itself, boundary included', async () => {
      const body = new FormData()
      body.set('file', 'contents')

      await oauth.fetch(`${origin()}/api/upload`, { method: 'POST', body })

      // defaulting to JSON here would strip the multipart boundary and break the upload — a non-string
      // body is left alone precisely so this cannot happen
      expect(seen[0]?.contentType).toContain('multipart/form-data')
      expect(seen[0]?.contentType).toContain('boundary=')
    })

    it('leaves a Blob to keep the type it was created with', async () => {
      await oauth.fetch(`${origin()}/api/upload`, { method: 'POST', body: new Blob(['a,b'], { type: 'text/csv' }) })

      expect(seen[0]?.contentType).toBe('text/csv')
    })

    it('leaves URLSearchParams to type itself', async () => {
      await oauth.fetch(`${origin()}/api/orders`, { method: 'POST', body: new URLSearchParams({ a: 'b' }) })

      expect(seen[0]?.contentType).toContain('application/x-www-form-urlencoded')
    })

    it('shares one refresh across concurrent calls', async () => {
      refresh.mockResolvedValue({ access_token: 'fresh', token_type: 'Bearer', expires_in: 60 })
      oauth.setConfig({ tokenPath: '/t', clientId: 'c' })
      oauth.setToken({ access_token: 'stale', token_type: 'Bearer', refresh_token: 'r', expires: Date.now() - 10_000 })

      await Promise.all([oauth.fetch(`${origin()}/api/a`), oauth.fetch(`${origin()}/api/b`), oauth.fetch(`${origin()}/api/c`)])

      // three requests, one refresh — checkToken's in-flight guard is what stops a thundering herd of
      // refreshes each invalidating the last one's refresh_token
      expect(refresh).toHaveBeenCalledTimes(1)
      expect(seen.every(r => r.authorization === 'Bearer fresh')).toBe(true)
    })

    it('keeps the caller headers', async () => {
      oauth.setToken({ access_token: 'at', token_type: 'Bearer' })

      const response = await oauth.fetch(`${origin()}/api/orders`, {
        method: 'POST',
        headers: { 'X-Custom': 'kept' },
        body: '{}'
      })

      expect(response.ok).toBe(true)
      expect(seen[0]?.authorization).toBe('Bearer at')
    })

    it('records a 401 body on the token and still lets the caller read it', async () => {
      oauth.setToken({ access_token: 'at' })
      respond = () => Response.json({ error: 'invalid_token' }, { status: 401 })

      const response = await oauth.fetch(`${origin()}/api/orders`)

      // the body is cloned, so storing it must not consume it
      expect(await response.json()).toEqual({ error: 'invalid_token' })
      expect(oauth.token()).toEqual({ error: 'invalid_token' })
      expect(oauth.hasError()).toBe(true)
    })

    it('clears the session on a 401 with no JSON body, without rejecting', async () => {
      oauth.setToken({ access_token: 'at' })
      // a gateway's HTML 401. There is no error to keep, and none is invented — but the unparseable body
      // must not turn the caller's request into a rejection
      respond = () => new Response('<html>401</html>', { status: 401, headers: { 'Content-Type': 'text/html' } })

      const response = await oauth.fetch(`${origin()}/api/orders`)

      expect(response.status).toBe(401)
      expect(oauth.token()).toEqual({})
      expect(oauth.isAuthorized()).toBe(false)
    })

    it('leaves the token alone on other statuses', async () => {
      const initial = { access_token: 'at' }
      oauth.setToken(initial)
      respond = () => new Response('boom', { status: 500 })

      const response = await oauth.fetch(`${origin()}/api/orders`)

      expect(response.status).toBe(500)
      expect(oauth.token()).toEqual(initial)
    })

    it('does not reject on a non-2xx — fetch semantics, not axios', async () => {
      respond = () => new Response('nope', { status: 403 })

      expect((await oauth.fetch(`${origin()}/api/orders`)).status).toBe(403)
    })
  })
})
