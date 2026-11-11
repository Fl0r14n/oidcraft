import { test } from 'bun:test'
import type { Adapter } from '../adapter'
import { adapterConformance } from './conformance'

export const bunConformance = (name: string, create: () => Adapter | Promise<Adapter>) => {
  for (const check of adapterConformance(create, { implements: ['identities', 'credentials', 'realms'] })) {
    test(`${name}: ${check.name}`, check.run)
  }
}
