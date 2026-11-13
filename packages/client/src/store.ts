// No framework import here or anything reachable from it: the bindings adapt `Subscribable` from outside.

/** The read side of a store; writes go through the instance's accessors. */
export interface Subscribable<S> {
  getState: () => S
  subscribe: (listener: (state: S, previous: S) => void) => () => void
}

export interface Store<S> extends Subscribable<S> {
  setState: (next: S) => void
}

/** Replaces the whole state; listeners run synchronously inside `setState`. */
export const createStore = <S>(initial: S): Store<S> => {
  let state = initial
  const listeners = new Set<(state: S, previous: S) => void>()

  return {
    getState: () => state,
    setState: next => {
      const previous = state
      if (Object.is(next, previous)) return
      state = next
      // a copy: a listener may subscribe or unsubscribe while the cascade runs
      for (const listener of [...listeners]) {
        listener(state, previous)
      }
    },
    subscribe: listener => {
      listeners.add(listener)
      return () => {
        listeners.delete(listener)
      }
    }
  }
}

// element-wise: a tuple selector returns a fresh array on every call
const defaultEquals = (a: any, b: any) =>
  Object.is(a, b) || (Array.isArray(a) && Array.isArray(b) && a.length === b.length && a.every((v, i) => Object.is(v, b[i])))

export interface WatchOptions<T> {
  immediate?: boolean
  equals?: (a: T, b: T) => boolean
}

/** Calls `callback` when `selector`'s value changes; tuples compare element-wise. Returns the unsubscribe. */
export const watchStore = <S, T>(
  store: Subscribable<S>,
  selector: (state: S) => T,
  callback: (value: T, previous: T | undefined) => void,
  options?: WatchOptions<T>
) => {
  const equals = options?.equals ?? defaultEquals
  let previous = selector(store.getState())
  if (options?.immediate) {
    callback(previous, undefined)
  }
  return store.subscribe(state => {
    const next = selector(state)
    if (!equals(next, previous)) {
      const prior = previous
      previous = next
      callback(next, prior)
    }
  })
}
