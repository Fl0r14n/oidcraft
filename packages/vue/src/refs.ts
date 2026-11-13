import type { Subscribable } from '@oidcraft/client'
import { watchStore } from '@oidcraft/client'
import { computed, onScopeDispose, type Ref, shallowRef, type WritableComputedRef } from 'vue'

/** A ref following `read()` on a `Subscribable` until the current scope ends; seeded synchronously, as `watchStore` fires on change. */
export const storeRef = <S, T>(store: Subscribable<S>, read: () => T): Ref<T> => {
  const state = shallowRef(read()) as Ref<T>
  onScopeDispose(
    watchStore(store, read, value => {
      state.value = value
    })
  )
  return state
}

/** `storeRef` for a value the caller may assign to; the write goes through `write`, so `token.value = {}` is persisted. */
export const writableStoreRef = <S, T>(store: Subscribable<S>, read: () => T, write: (value: T) => void): WritableComputedRef<T> => {
  const state = storeRef(store, read)
  return computed({
    get: () => state.value,
    set: write
  })
}
