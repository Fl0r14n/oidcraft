import { describe, expect, test } from 'bun:test'
import type { Adapter } from './index'
import { adapter, build, ISSUER, useFlow } from './test-flow'

useFlow()

// NFR-D5: without it a 500 leaves no trace the host can find.
describe('an unexpected failure is reported to the host', () => {
  const failing = (): Adapter => ({
    ...adapter,
    keys: {
      async active() {
        throw new Error('the key store is down')
      }
    }
  })

  test('with its cause and the request, and none of it in the response', async () => {
    const seen: { error: unknown; request: Request }[] = []
    const provider = build({
      adapter: failing(),
      onError: (error: unknown, context: { request: Request }) => void seen.push({ error, ...context })
    })
    const response = await provider.handle(new Request(`${ISSUER}/jwks`))
    expect(response.status).toBe(500)
    expect(await response.json()).toEqual({ error: 'server_error', error_description: 'unexpected failure' })
    expect(seen).toHaveLength(1)
    expect(String(seen[0]?.error)).toContain('the key store is down')
    expect(seen[0]?.request.url).toBe(`${ISSUER}/jwks`)
  })

  test('a refusal the provider meant is not reported', async () => {
    const seen: unknown[] = []
    const provider = build({ onError: (error: unknown) => void seen.push(error) })
    expect((await provider.handle(new Request(`${ISSUER}/userinfo`))).status).toBe(401)
    expect(seen).toHaveLength(0)
  })

  test('a hook that throws does not replace the answer', async () => {
    const provider = build({
      adapter: failing(),
      onError: () => {
        throw new Error('the logger is down too')
      }
    })
    expect((await provider.handle(new Request(`${ISSUER}/jwks`))).status).toBe(500)
  })
})
