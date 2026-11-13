/// <reference types="bun" />
import type { RequestContext } from '@oidcraft/provider'

type BunServer = { requestIP(request: Request): { address: string } | null }

/** Supplies only what `Request` omits (FR-R4). Bun exposes no peer certificate, so mTLS client auth is unavailable here (G-8). */
export const bunContext =
  (server: BunServer) =>
  (request: Request): RequestContext => ({
    clientIp: server.requestIP(request)?.address
  })

/** argon2id through `Bun.password`, for `@oidcraft/provider/accounts` (FR-I7). PHC strings, so a Node host can verify them too. */
export const bunPasswordHasher = {
  hash: (password: string) => Bun.password.hash(password, { algorithm: 'argon2id', memoryCost: 65536, timeCost: 3 }),
  verify: (password: string, hash: string) => Bun.password.verify(password, hash)
}
