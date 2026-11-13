import type { RequestContext } from '@oidcraft/provider'

export type DenoServeInfo = { remoteAddr: { hostname?: string } }

/** `Deno.serve` takes the core's handler directly; the peer address arrives as its second argument. */
export const denoContext = (_request: Request, info: DenoServeInfo): RequestContext => ({
  clientIp: info.remoteAddr.hostname
})
