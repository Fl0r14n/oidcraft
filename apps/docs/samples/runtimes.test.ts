/// <reference types="bun" />
import { afterAll, describe, expect, test } from 'bun:test'
import { createServer } from 'node:http'
import { memoryAdapter } from '@oidcraft/adapter/memory'
import { ConfigurationError, createProvider } from '@oidcraft/provider'
import { bunContext, bunPasswordHasher } from '@oidcraft/provider/runtimes/bun'
import { denoContext } from '@oidcraft/provider/runtimes/deno'
import { toFastifyPlugin } from '@oidcraft/provider/runtimes/fastify'
import { nodePasswordHasher, toNodeHandler } from '@oidcraft/provider/runtimes/node'
import { type IncomingCf, workerdContext } from '@oidcraft/provider/runtimes/workerd'
import express from 'express'
import Fastify from 'fastify'

const adapter = await memoryAdapter()

// #region issuer
const issuer = 'https://auth.example.com'
const provider = createProvider({ issuer, adapter, interactionUrl: `${issuer}/interaction` })
// #endregion issuer

const discovery = async (response: Response | Promise<Response>) => {
  const answered = await response
  expect(answered.status).toBe(200)
  return (await answered.json()).issuer
}

const hostile = { host: 'evil.example.net', 'x-forwarded-host': 'evil.example.net', 'x-forwarded-proto': 'http' }

describe('bun', () => {
  // #region bun
  const server = Bun.serve({
    port: 0,
    fetch: (request, server) => provider.handle(request, bunContext(server)(request))
  })
  // #endregion bun

  afterAll(() => server.stop())

  test('serves the provider, with the configured issuer whatever the request says', async () => {
    expect(await discovery(fetch(new URL('/.well-known/openid-configuration', server.url)))).toBe(issuer)
    expect(await discovery(fetch(new URL('/.well-known/openid-configuration', server.url), { headers: hostile }))).toBe(issuer)
  })

  test('the context carries the peer address and never a certificate', async () => {
    const seen = Bun.serve({
      port: 0,
      fetch: (request, server) => Response.json(bunContext(server)(request))
    })
    const context = await (await fetch(seen.url)).json()
    seen.stop()
    expect(context.clientIp).toBeOneOf(['127.0.0.1', '::1', '::ffff:127.0.0.1'])
    expect(context.clientCertificate).toBeUndefined()
  })
})

describe('node', () => {
  // #region node
  const server = createServer(toNodeHandler(provider.handle, issuer)).listen(0, '127.0.0.1')
  // #endregion node

  afterAll(() => server.close())

  test('serves the provider through node:http', async () => {
    if (!server.listening) await new Promise(resolve => server.once('listening', resolve))
    const { port } = server.address() as { port: number }
    const url = `http://127.0.0.1:${port}/.well-known/openid-configuration`
    expect(await discovery(fetch(url))).toBe(issuer)
    expect(await discovery(fetch(url, { headers: hostile }))).toBe(issuer)
  })
})

describe('express', () => {
  const oidcIssuer = 'https://example.com/oidc'
  const oidc = createProvider({ issuer: oidcIssuer, adapter, interactionUrl: `${oidcIssuer}/interaction` })
  // #region express
  const app = express()
  app.use('/oidc', toNodeHandler(oidc.handle, oidcIssuer))
  app.use(express.json(), express.urlencoded())
  app.post('/api/echo', (request, response) => {
    response.json(request.body)
  })
  // #endregion express
  const server = app.listen(0, '127.0.0.1')
  const base = async () => {
    if (!server.listening) await new Promise(resolve => server.once('listening', resolve))
    return `http://127.0.0.1:${(server.address() as { port: number }).port}`
  }

  afterAll(() => server.close())

  test('serves the provider under its mount path', async () => {
    expect(await discovery(fetch(`${await base()}/oidc/.well-known/openid-configuration`, { headers: hostile }))).toBe(oidcIssuer)
  })

  test('the provider reads a form body no parser has consumed', async () => {
    const response = await fetch(`${await base()}/oidc/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'grant_type=authorization_code&client_id=ghost'
    })
    expect((await response.json()).error).toBe('invalid_client')
  })

  test("the app's own routes keep their parsers", async () => {
    const response = await fetch(`${await base()}/api/echo`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{"x":1}'
    })
    expect(await response.json()).toEqual({ x: 1 })
  })
})

describe('fastify', () => {
  test('serves the provider beside the app routes', async () => {
    // #region fastify
    const app = Fastify()
    await app.register(toFastifyPlugin(provider.handle, issuer))
    // #endregion fastify
    const base = await app.listen({ port: 0, host: '127.0.0.1' })
    expect(await discovery(fetch(`${base}/.well-known/openid-configuration`, { headers: hostile }))).toBe(issuer)
    await app.close()
  })
})

describe('deno', () => {
  // #region deno
  const handler = (request: Request, info: { remoteAddr: { hostname: string } }) => provider.handle(request, denoContext(request, info))
  // #endregion deno

  test('the handler Deno.serve is given answers with the configured issuer', async () => {
    const request = new Request('https://evil.example.net/.well-known/openid-configuration', { headers: hostile })
    expect(await discovery(handler(request, { remoteAddr: { hostname: '198.51.100.4' } }))).toBe(issuer)
    expect(denoContext(request, { remoteAddr: { hostname: '198.51.100.4' } })).toEqual({ clientIp: '198.51.100.4' })
  })
})

describe('workerd', () => {
  // #region workerd
  type CfRequest = Request & { cf?: IncomingCf }

  const worker = {
    fetch: (request: CfRequest) => provider.handle(request, workerdContext(request, request.cf))
  }
  // #endregion workerd

  test('the worker answers with the configured issuer, and takes the address from CF-Connecting-IP', async () => {
    const request = new Request('https://evil.example.net/.well-known/openid-configuration', {
      headers: { ...hostile, 'cf-connecting-ip': '192.0.2.9' }
    })
    expect(await discovery(worker.fetch(request))).toBe(issuer)
    expect(workerdContext(request).clientIp).toBe('192.0.2.9')
  })
})

describe('mTLS', () => {
  test('a certificate method on a runtime that cannot supply one is refused at construction', () => {
    // #region mtls-refused
    const build = () =>
      createProvider({
        issuer,
        adapter,
        interactionUrl: `${issuer}/interaction`,
        clientAuthMethods: ['private_key_jwt', 'tls_client_auth']
      })
    // #endregion mtls-refused
    expect(build).toThrow(ConfigurationError)
    expect(build).toThrow(/tls_client_auth cannot work here/)
  })

  test('declaring the capability advertises the methods and certificate-bound tokens', async () => {
    // #region mtls-node
    const mtls = createProvider({
      issuer,
      adapter,
      interactionUrl: `${issuer}/interaction`,
      clientAuthMethods: ['private_key_jwt', 'self_signed_tls_client_auth'],
      capabilities: { clientCertificate: true }
    })
    // #endregion mtls-node
    const metadata = await (await mtls.handle(new Request(`${issuer}/.well-known/openid-configuration`))).json()
    expect(metadata.token_endpoint_auth_methods_supported).toEqual(['private_key_jwt', 'self_signed_tls_client_auth'])
    expect(metadata.tls_client_certificate_bound_access_tokens).toBe(true)
  })
})

describe('password hashers', () => {
  test('Bun and Node write the same PHC argon2id strings, so each verifies the other', async () => {
    // #region hashers
    const fromBun = await bunPasswordHasher.hash('correct horse battery')
    const fromNode = await nodePasswordHasher.hash('correct horse battery')

    const verified = [
      await nodePasswordHasher.verify('correct horse battery', fromBun),
      await bunPasswordHasher.verify('correct horse battery', fromNode)
    ]
    // #endregion hashers
    expect(fromNode).toStartWith('$argon2id$v=19$m=65536,t=3,p=4$')
    expect(verified).toEqual([true, true])
    expect(await nodePasswordHasher.verify('wrong horse battery', fromBun)).toBe(false)
  })
})
