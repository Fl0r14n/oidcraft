import type { ResolvedConfig } from '../config'
import { jwksResponseBody } from '../keys'

/** Cacheable and served without a storage read on the hot path is the goal; the adapter decides (NFR-P2). */
export const jwksEndpoint = async (config: ResolvedConfig) => {
  const keys = await config.adapter.keys.active()
  return Response.json(jwksResponseBody(keys), {
    headers: { 'cache-control': 'public, max-age=300, stale-while-revalidate=3600' }
  })
}
