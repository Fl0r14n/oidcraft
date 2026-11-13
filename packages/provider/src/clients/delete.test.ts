import { expect, test } from 'bun:test'
import { memoryAdapter } from '@oidcraft/adapter/memory'
import type { ResolvedConfig } from '../config'
import { deleteClient } from './delete'

// FR-T3, FR-T7: the grants go before the tokens, so a redemption already past its grant check writes into a grant that is gone.
test('deleting a client destroys its grants before its tokens', async () => {
  const adapter = await memoryAdapter()
  const order: string[] = []
  const config = {
    adapter: {
      ...adapter,
      grants: { ...adapter.grants, destroyByClientId: async (id: string) => void order.push(`grants:${id}`) },
      artifacts: { ...adapter.artifacts, revokeByClientId: async (id: string) => void order.push(`artifacts:${id}`) }
    }
  } as unknown as ResolvedConfig
  await deleteClient(config, 'rp')
  expect(order).toEqual(['grants:rp', 'artifacts:rp'])
})
