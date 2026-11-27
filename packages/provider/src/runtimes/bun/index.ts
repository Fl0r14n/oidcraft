/// <reference types="bun" />
import { createSafeFetch, type ProxyTrust, proxiedClientIp, type RequestContext } from '@oidcraft/provider'

type BunServer = { requestIP(request: Request): { address: string } | null }

/**
 * Supplies only what `Request` omits (FR-R4). Bun exposes no peer certificate, so mTLS client auth is unavailable here (G-8).
 * Behind a proxy that is the only way in, `trustProxy` names the header it reports the client in; otherwise every client
 * is the proxy's address.
 */
export const bunContext =
  (server: BunServer, options: { trustProxy?: ProxyTrust } = {}) =>
  (request: Request): RequestContext => ({
    clientIp: proxiedClientIp(request.headers, options.trustProxy) ?? server.requestIP(request)?.address
  })

/** argon2id through `Bun.password`, for `@oidcraft/provider/accounts` (FR-I7). PHC strings, so a Node host can verify them too. */
export const bunPasswordHasher = {
  hash: (password: string) => Bun.password.hash(password, { algorithm: 'argon2id', memoryCost: 65536, timeCost: 3 }),
  verify: (password: string, hash: string) => Bun.password.verify(password, hash)
}

/**
 * `fetch` for a URL a client chose (NFR-S14): every address the name resolves to must be public. Bun's `fetch` takes no
 * address to connect to, so it resolves the name again: a name that rebinds between the two is not caught.
 */
export const safeFetch = createSafeFetch({
  resolve: async hostname => (await Bun.dns.lookup(hostname)).map(({ address }) => address),
  send: (url, init) => fetch(url, init)
})
