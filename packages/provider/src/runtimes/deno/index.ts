import { createSafeFetch, type RequestContext } from '@oidcraft/provider'

export type DenoServeInfo = { remoteAddr: { hostname?: string } }

/** `Deno.serve` takes the core's handler directly; the peer address arrives as its second argument. */
export const denoContext = (_request: Request, info: DenoServeInfo): RequestContext => ({
  clientIp: info.remoteAddr.hostname
})

declare const Deno: { resolveDns(name: string, type: 'A' | 'AAAA'): Promise<string[]> }

const records = (hostname: string, type: 'A' | 'AAAA') => Deno.resolveDns(hostname, type).catch(() => [] as string[])

/**
 * `fetch` for a URL a client chose (NFR-S14): every address the name resolves to must be public. Deno's `fetch` takes no
 * address to connect to, so it resolves the name again: a name that rebinds between the two is not caught.
 */
export const safeFetch = createSafeFetch({
  resolve: async hostname => [...(await records(hostname, 'A')), ...(await records(hostname, 'AAAA'))],
  send: (url, init) => fetch(url, init)
})
