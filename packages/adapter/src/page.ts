import type { Client } from './types'

/** `ordered` must already be in client id order and past the cursor; the returned cursor is the page's last id. */
export const page = (ordered: Client[], limit: number | undefined) => {
  if (limit === undefined || ordered.length <= limit) return { clients: ordered }
  const clients = ordered.slice(0, limit)
  return { clients, cursor: (clients.at(-1) as Client).clientId }
}
