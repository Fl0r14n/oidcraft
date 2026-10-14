/// <reference types="bun" />
import type { RequestContext } from 'oidcraft'

type BunServer = { requestIP(request: Request): { address: string } | null }

/**
 * `Bun.serve` takes the core's handler directly — this supplies only what `Request` omits (FR-R4).
 *
 * Bun's `Server` exposes no peer-certificate accessor, so `clientCertificate` is always absent and
 * the mTLS client-authentication methods are unavailable on this runtime (REQUIREMENTS.md `G-8`).
 */
export const bunContext =
  (issuer: string, server: BunServer) =>
  (request: Request): RequestContext => ({
    issuer,
    clientIp: server.requestIP(request)?.address
  })

/** argon2id through `Bun.password`, for `oidcraft/accounts` (FR-I7). PHC strings, so a Node host can verify them too. */
export const bunPasswordHasher = {
  hash: (password: string) => Bun.password.hash(password, { algorithm: 'argon2id', memoryCost: 65536, timeCost: 3 }),
  verify: (password: string, hash: string) => Bun.password.verify(password, hash)
}
