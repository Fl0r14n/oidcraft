import { afterAll, describe, expect, test } from 'bun:test'
import { memoryAdapter } from '@oidcraft/adapter/memory'
import Fastify from 'fastify'
import type { RequestContext } from '../../context'
import { createProvider } from '../../provider'
import { toFastifyPlugin } from './index'

const adapter = await memoryAdapter()
const provider = createProvider({ interactionUrl: 'https://op.example.com/interaction', issuer: 'http://127.0.0.1/oidc', adapter })

let seen: { body: string; context: RequestContext } | undefined
const echo = async (request: Request, context: RequestContext) => {
  seen = { body: await request.text(), context }
  const headers = new Headers({ 'content-type': 'text/plain' })
  headers.append('set-cookie', 'a=1; Path=/')
  headers.append('set-cookie', 'b=2; Path=/')
  return new Response('echoed', { status: 201, headers })
}

/** The plugin only proves anything inside a real Fastify app, beside routes whose parsers it must not disturb (FR-R3). */
const app = Fastify()
app.post('/api/json', async request => ({ parsed: request.body }))
await app.register(toFastifyPlugin(provider.handle, 'http://127.0.0.1/oidc'), { prefix: '/oidc' })
await app.register(toFastifyPlugin(echo, 'http://127.0.0.1/echo'), { prefix: '/echo' })
const broken = async () => {
  throw new Error('the bridge broke')
}
await app.register(toFastifyPlugin(broken, 'http://127.0.0.1/broken'), { prefix: '/broken' })
const base = await app.listen({ port: 0, host: '127.0.0.1' })

afterAll(() => app.close())

describe('fastify plugin', () => {
  test('serves discovery under the issuer path', async () => {
    const response = await fetch(`${base}/oidc/.well-known/openid-configuration`)
    expect(response.status).toBe(200)
    expect((await response.json()).token_endpoint).toBe('http://127.0.0.1/oidc/token')
  })

  test('carries a form body through to the provider, unparsed by Fastify', async () => {
    const response = await fetch(`${base}/oidc/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'grant_type=authorization_code&client_id=ghost'
    })
    expect(response.status).toBe(401)
    expect((await response.json()).error).toBe('invalid_client')
  })

  test('preserves the status and the OAuth error shape', async () => {
    const response = await fetch(`${base}/oidc/nope`)
    expect(response.status).toBe(404)
    expect((await response.json()).error).toBe('invalid_request')
  })

  test('hands over the body, the client address, and every Set-Cookie', async () => {
    const response = await fetch(`${base}/echo/anything`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{"x":1}'
    })
    expect(response.status).toBe(201)
    expect(await response.text()).toBe('echoed')
    expect(response.headers.getSetCookie()).toEqual(['a=1; Path=/', 'b=2; Path=/'])
    expect(seen?.body).toBe('{"x":1}')
    expect(seen?.context.clientIp).toBe('127.0.0.1')
  })

  test("leaves the app's own routes and parsers alone", async () => {
    const response = await fetch(`${base}/api/json`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"x":1}' })
    expect(await response.json()).toEqual({ parsed: { x: 1 } })
  })

  test('answers 500 rather than hanging when the bridge throws', async () => {
    expect((await fetch(`${base}/broken/token`)).status).toBe(500)
  })
})
