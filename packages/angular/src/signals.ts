import { DestroyRef, inject, type Signal, signal, type WritableSignal } from '@angular/core'
import { type Subscribable, watchStore } from '@oidcraft/client'

/**
 * Angular's half of the binding, and all of it. `@oidcraft/client` holds the state and publishes a
 * `Subscribable`; these two turn one into a signal and stop following it when the injector is
 * destroyed.
 *
 * Seeded synchronously rather than from the first callback, because `watchStore` fires on *change* —
 * a value already correct at creation and never moving would otherwise never arrive.
 */
export const storeSignal = <S, T>(store: Subscribable<S>, read: () => T): Signal<T> => {
  const state = signal(read())
  inject(DestroyRef).onDestroy(
    watchStore(store, read, value => {
      state.set(value)
    })
  )
  return state.asReadonly()
}

/**
 * The same for a signal callers may write, keeping `token.set(...)` working as it did.
 *
 * `set` and `update` are replaced so a write reaches the accessor that owns persistence rather than
 * only this signal — otherwise a redirect straight after an assignment loses the handoff it was
 * meant to carry. The subscription keeps the *original* setter, captured first: routing it through
 * the replacement would write back to storage on every read-back.
 */
export const writableStoreSignal = <S, T>(store: Subscribable<S>, read: () => T, write: (value: T) => void): WritableSignal<T> => {
  const state = signal(read())
  const native = state.set.bind(state)
  inject(DestroyRef).onDestroy(watchStore(store, read, native))
  state.set = write
  state.update = fn => write(fn(state()))
  return state
}
