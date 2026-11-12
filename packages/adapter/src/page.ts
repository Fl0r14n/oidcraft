import type { Client } from './types'

/** One page of clients already in client id order and past the cursor: the cursor is the last id, while more may follow. */
export const page = (ordered: Client[], limit: number | undefined) => {
  if (limit === undefined || ordered.length <= limit) return { clients: ordered }
  const clients = ordered.slice(0, limit)
  return { clients, cursor: (clients.at(-1) as Client).clientId }
}
