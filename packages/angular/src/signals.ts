import { DestroyRef, inject, type Signal, signal, type WritableSignal } from '@angular/core'
import { type Subscribable, watchStore } from '@oidcraft/client'

/** A signal following `read()` on a `Subscribable` until the injector is destroyed; seeded now, as `watchStore` fires on change. */
export const storeSignal = <S, T>(store: Subscribable<S>, read: () => T): Signal<T> => {
  const state = signal(read())
  inject(DestroyRef).onDestroy(
    watchStore(store, read, value => {
      state.set(value)
    })
  )
  return state.asReadonly()
}

/** `storeSignal` for a value callers may write; `set` and `update` go through `write`, so the write is persisted. */
export const writableStoreSignal = <S, T>(store: Subscribable<S>, read: () => T, write: (value: T) => void): WritableSignal<T> => {
  const state = signal(read())
  // the original setter: the subscription routed through `write` would persist every read-back
  const native = state.set.bind(state)
  inject(DestroyRef).onDestroy(watchStore(store, read, native))
  state.set = write
  state.update = fn => write(fn(state()))
  return state
}
