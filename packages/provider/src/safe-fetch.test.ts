import { describe, expect, test } from 'bun:test'
import { safeFetch as nodeSafeFetch } from './runtimes/node'
import { createSafeFetch, isPublicAddress, UnsafeFetchError } from './safe-fetch'

describe('isPublicAddress (RFC 6890)', () => {
  test.each([
    ['8.8.8.8', true],
    ['1.1.1.1', true],
    ['127.0.0.1', false],
    ['10.1.2.3', false],
    ['172.16.0.1', false],
    ['192.168.1.1', false],
    ['169.254.169.254', false],
    ['100.64.0.1', false],
    ['0.0.0.0', false],
    ['224.0.0.1', false],
    ['2606:4700:4700::1111', true],
    ['::1', false],
    ['::', false],
    ['::ffff:127.0.0.1', false],
    ['::ffff:8.8.8.8', true],
    ['64:ff9b::a9fe:a9fe', false],
    ['fe80::1', false],
    ['fc00::1', false],
    ['ff02::1', false],
    ['2001:db8::1', false],
    ['[::1]', false],
    ['localhost', false],
    ['999.1.1.1', false]
  ])('%s is %s', (address, expected) => {
    expect(isPublicAddress(address)).toBe(expected)
  })
})

describe('createSafeFetch (NFR-S14)', () => {
  const sent: string[] = []
  const guarded = (resolved: string[], answer: () => Response = () => new Response('{}')) =>
    createSafeFetch({
      resolve: async () => resolved,
      send: async url => {
        sent.push(url.href)
        return answer()
      }
    })

  test('refuses http, credentials, and a name with any address that is not public, before sending', async () => {
    sent.length = 0
    await expect(guarded(['8.8.8.8'])('http://rp.example.com/jwks')).rejects.toThrow(UnsafeFetchError)
    await expect(guarded(['8.8.8.8'])('https://user:pw@rp.example.com/jwks')).rejects.toThrow(/credentials/)
    await expect(guarded(['8.8.8.8', '10.0.0.5'])('https://rp.example.com/jwks')).rejects.toThrow(/not a public address/)
    await expect(guarded([])('https://rp.example.com/jwks')).rejects.toThrow(/not a public address/)
    await expect(guarded([])('https://[::1]/jwks')).rejects.toThrow(/not a public address/)
    expect(sent).toEqual([])
  })

  test('fetches a public name, and never follows a redirect', async () => {
    expect(await (await guarded(['8.8.8.8'])('https://rp.example.com/jwks')).json()).toEqual({})
    const redirecting = guarded(['8.8.8.8'], () => new Response(null, { status: 302, headers: { location: 'https://169.254.169.254/' } }))
    await expect(redirecting('https://rp.example.com/jwks')).rejects.toThrow(/redirects/)
  })

  test('refuses a body over its cap', async () => {
    const big = guarded(['8.8.8.8'], () => new Response('x'.repeat(2_000)))
    await expect(big('https://rp.example.com/jwks', { maxBytes: 1_000 })).rejects.toThrow(/over 1000 bytes/)
    expect(await (await big('https://rp.example.com/jwks', { maxBytes: 4_000 })).text()).toHaveLength(2_000)
  })

  test('without a resolver, as on workerd, a name is not checked but an address literal still is', async () => {
    const unresolved = createSafeFetch({ send: async () => new Response('ok') })
    expect(await (await unresolved('https://rp.example.com/')).text()).toBe('ok')
    await expect(unresolved('https://169.254.169.254/latest/meta-data')).rejects.toThrow(/not a public address/)
  })

  test("Node's refuses a name that resolves to loopback", async () => {
    await expect(nodeSafeFetch('https://localhost/jwks')).rejects.toThrow(/not a public address/)
  })
})
