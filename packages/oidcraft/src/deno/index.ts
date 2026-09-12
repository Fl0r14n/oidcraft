import type { RequestContext } from 'oidcraft'

type DenoServeInfo = { remoteAddr: { hostname?: string } }

/** `Deno.serve` takes the core's handler directly; the peer address arrives as its second argument. */
export const denoContext =
  (issuer: string) =>
  (_request: Request, info: DenoServeInfo): RequestContext => ({
    issuer,
    clientIp: info.remoteAddr.hostname
  })
