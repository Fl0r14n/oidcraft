import type { RequestContext } from '@oidcraft/provider'
import { type NodeBridgeOptions, toNodeHandler } from '@oidcraft/provider/runtimes/node'
import type { FastifyInstance } from 'fastify'

/**
 * Mounts a provider on Fastify, Nest's Fastify adapter included, through the Node bridge:
 * `app.register(toFastifyPlugin(provider.handle, issuer), { prefix: new URL(issuer).pathname })`.
 */
export const toFastifyPlugin = (
  handle: (request: Request, context: RequestContext) => Promise<Response>,
  issuer: string,
  options: NodeBridgeOptions = {}
) => {
  const bridge = toNodeHandler(handle, issuer, options)
  return async (instance: FastifyInstance) => {
    // Fastify reads a body before its handler runs; this scope leaves it unread for the bridge to stream (FR-R3).
    instance.removeAllContentTypeParsers()
    instance.addContentTypeParser('*', (_request, _payload, done) => done(null))
    instance.all('/*', async (request, reply) => {
      reply.hijack()
      try {
        await bridge(request.raw, reply.raw)
      } catch (error) {
        // A hijacked reply is never answered by Fastify: without this the request hangs.
        request.log.error(error)
        if (reply.raw.headersSent) reply.raw.destroy()
        else reply.raw.writeHead(500).end()
      }
    })
  }
}
