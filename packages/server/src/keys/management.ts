import type { ResolvedConfig } from '../config'
import { jwksResponseBody } from './keys'

export const keyManagement = (config: ResolvedConfig) => ({
  /** Public members only: an admin screen has no more business seeing a private key than anyone else. */
  async list() {
    return jwksResponseBody(await config.adapter.keys.active()).keys
  }
})
