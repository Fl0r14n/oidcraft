import { createStore, type Subscribable } from './store'

export const readSlot = (key: string) => {
  try {
    const value = globalThis.localStorage?.getItem(key)
    return (value && JSON.parse(value)) || undefined
  } catch {
    return undefined
  }
}

export const writeSlot = (key: string, value: any) => {
  try {
    globalThis.localStorage?.setItem(key, JSON.stringify(value))
  } catch {
    /* in-memory state stands on its own */
  }
}

export interface StorageStore<T> {
  store: Subscribable<{ value: T }>
  get: () => T
  set: (value: T) => void
  /** re-point at another storage key: load that key's value without writing it back */
  rekey: (key: string) => void
  /** read the current key again: another tab's write may not have reached this one as an event yet */
  reload: () => void
  /** start following other tabs' writes to the current key. Returns the teardown. */
  listen: () => () => void
}

export const createStorageStore = <T>(initialKey: string, initial: T, map?: (v: any) => T): StorageStore<T> => {
  const seed = (key: string): T => {
    const stored = readSlot(key)
    return map?.(stored || initial) || stored || initial
  }

  let key = initialKey
  const store = createStore<{ value: T }>({ value: seed(initialKey) })

  return {
    store,
    get: () => store.getState().value,
    // written before the notify: a listener may navigate away
    set: value => {
      writeSlot(key, value)
      store.setState({ value })
    },
    rekey: newKey => {
      if (newKey === key) return
      key = newKey
      store.setState({ value: seed(newKey) })
    },
    reload: () => store.setState({ value: seed(key) }),
    listen: () => {
      const onStorage = (event: StorageEvent) => {
        if (event.key !== null && event.key !== key) return
        store.setState({ value: seed(key) })
      }
      globalThis.addEventListener?.('storage', onStorage)
      return () => globalThis.removeEventListener?.('storage', onStorage)
    }
  }
}
