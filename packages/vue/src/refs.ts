import type { Subscribable } from '@oidcraft/client'
import { watchStore } from '@oidcraft/client'
import { computed, onScopeDispose, type Ref, shallowRef, type WritableComputedRef } from 'vue'

/**
 * The whole Vue binding, in two functions. `@oidcraft/client` holds the state and publishes a
 * `Subscribable`; everything below turns one into a ref and stops following it when the scope ends.
 *
 * Seeded synchronously rather than on the first subscription callback, because `watchStore` fires on
 * *change* — a value that is already correct at creation and never moves would otherwise never arrive.
 */
export const storeRef = <S, T>(store: Subscribable<S>, read: () => T): Ref<T> => {
  const state = shallowRef(read()) as Ref<T>
  onScopeDispose(
    watchStore(store, read, value => {
      state.value = value
    })
  )
  return state
}

/** The same, for a value the caller may assign to. The write goes to the accessor that owns
 * persistence rather than to the ref, so `token.value = {}` still reaches localStorage. */
export const writableStoreRef = <S, T>(store: Subscribable<S>, read: () => T, write: (value: T) => void): WritableComputedRef<T> => {
  const state = storeRef(store, read)
  return computed({
    get: () => state.value,
    set: write
  })
}
