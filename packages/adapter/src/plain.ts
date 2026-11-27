/** Every name an object answers to, its own and its prototypes', short of `Object.prototype`. */
const namesOf = (value: object) => {
  const names = new Set<string>()
  for (let level: object | null = value; level && level !== Object.prototype; level = Object.getPrototypeOf(level)) {
    for (const name of Object.getOwnPropertyNames(level)) if (name !== 'constructor') names.add(name)
  }
  return names
}

/**
 * The store as a plain object: each method, own or inherited, bound to the original. A class's methods live on its prototype,
 * which a spread drops, so a class-based store wrapped by spreading would lose them (A1).
 */
export const toPlainStore = <T extends object>(store: T): T => {
  const plain: Record<string, unknown> = {}
  for (const name of namesOf(store)) {
    const value = (store as Record<string, unknown>)[name]
    plain[name] = typeof value === 'function' ? value.bind(store) : value
  }
  return plain as T
}

/** Every store of the adapter made plain, so the provider may wrap any of them by spreading. */
export const toPlainAdapter = <A extends object>(adapter: A): A => {
  const plain: Record<string, unknown> = {}
  for (const name of namesOf(adapter)) {
    const store = (adapter as Record<string, unknown>)[name]
    plain[name] = store && typeof store === 'object' ? toPlainStore(store) : store
  }
  return plain as A
}
