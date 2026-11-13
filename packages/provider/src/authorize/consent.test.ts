import { expect, test } from 'bun:test'
import { memoryAdapter } from '@oidcraft/adapter/memory'
import type { ResolvedConfig } from '../config'
import { recordConsent } from './consent'

// FR-I4: two first consents for different scopes, at once, from two tabs.
test('racing first consents end with every scope either consented to', async () => {
  const adapter = await memoryAdapter()
  const config = { adapter } as ResolvedConfig
  await Promise.all([recordConsent(config, 'ada', 'rp', ['openid', 'profile']), recordConsent(config, 'ada', 'rp', ['openid', 'email'])])
  const grants = await adapter.grants.listForAccount('ada')
  expect(grants).toHaveLength(1)
  expect(grants[0]?.scopes.toSorted()).toEqual(['email', 'openid', 'profile'])
})
