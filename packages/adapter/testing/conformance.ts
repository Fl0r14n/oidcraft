import { test } from 'bun:test'
import type { Adapter } from '@oidcraft/adapter'
import { adapterConformance } from '@oidcraft/adapter/conformance'

/** The shared suite under bun:test, for the first-party adapters' own tests. Not published. */
export const bunConformance = (name: string, create: () => Adapter | Promise<Adapter>) => {
  for (const check of adapterConformance(create, { implements: ['identities', 'credentials', 'realms'] })) {
    test(`${name}: ${check.name}`, check.run)
  }
}
