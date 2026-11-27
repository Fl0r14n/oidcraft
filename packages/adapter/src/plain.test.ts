import { describe, expect, test } from 'bun:test'
import { toPlainAdapter, toPlainStore } from './plain'

class Counter {
  #count = 0
  readonly label = 'counter'
  bump() {
    this.#count += 1
    return this.#count
  }
}

class Doubled extends Counter {
  twice() {
    this.bump()
    return this.bump()
  }
}

// A1: a spread copies own enumerable properties only, so a class's methods, on its prototype, were lost inside the provider.
describe('toPlainStore', () => {
  test('a class instance keeps its own and inherited methods, bound to it, through a spread', () => {
    const store = new Doubled()
    expect({ ...store }).not.toHaveProperty('bump')
    const wrapped = { ...toPlainStore(store) } as Doubled
    expect(wrapped.twice()).toBe(2)
    expect(wrapped.bump()).toBe(3)
    expect(store.bump()).toBe(4)
    expect(wrapped.label).toBe('counter')
  })

  test('a plain object comes back with the same methods', () => {
    const store = { find: async (id: string) => id }
    expect(Object.keys(toPlainStore(store))).toEqual(['find'])
  })
})

describe('toPlainAdapter', () => {
  test('every store, a class adapter whose stores are getters included, is made plain', () => {
    class Adapter {
      readonly #counter = new Doubled()
      get counter() {
        return this.#counter
      }
    }
    const plain = { ...toPlainAdapter(new Adapter()) } as { counter: Doubled }
    expect(({ ...plain.counter } as Doubled).twice()).toBe(2)
  })
})
