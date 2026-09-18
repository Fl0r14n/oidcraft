import { describe, expect, it } from 'bun:test'
import { createStore, watchStore } from './store'

describe('createStore', () => {
  it('notifies subscribers with the next and previous state', () => {
    const store = createStore({ a: 1 })
    const seen: Array<[number, number]> = []
    store.subscribe((state, previous) => seen.push([state.a, previous.a]))

    store.setState({ a: 2 })
    store.setState({ a: 3 })

    expect(seen).toEqual([
      [2, 1],
      [3, 2]
    ])
  })

  it('replaces the state rather than merging it', () => {
    const store = createStore<{ a: number; b?: number }>({ a: 1, b: 2 })
    store.setState({ a: 9 })
    expect(store.getState()).toEqual({ a: 9 })
  })

  it('bails when the next state is the same reference', () => {
    const state = { a: 1 }
    const store = createStore(state)
    let calls = 0
    store.subscribe(() => {
      calls++
    })

    store.setState(state)

    expect(calls).toBe(0)
  })

  it('stops delivering after unsubscribe', () => {
    const store = createStore({ a: 1 })
    let calls = 0
    const unsubscribe = store.subscribe(() => {
      calls++
    })

    store.setState({ a: 2 })
    unsubscribe()
    store.setState({ a: 3 })

    expect(calls).toBe(1)
    expect(store.getState()).toEqual({ a: 3 })
  })

  it('a listener unsubscribed mid-cascade still receives the write in flight', () => {
    const store = createStore({ a: 1 })
    const order: string[] = []
    let unsubscribeSecond = () => {}
    // the first listener tears the second one down while the cascade is running. The copy taken in
    // setState is a snapshot, so the second still sees this write and is gone from the next one —
    // deliberately unlike iterating the live Set, where removal mid-iteration silently skips it
    store.subscribe(() => {
      order.push('first')
      unsubscribeSecond()
    })
    unsubscribeSecond = store.subscribe(() => order.push('second'))

    store.setState({ a: 2 })
    store.setState({ a: 3 })

    expect(order).toEqual(['first', 'second', 'first'])
  })

  it('a listener subscribing mid-cascade is not called for the write in flight', () => {
    const store = createStore({ a: 1 })
    const late: number[] = []
    store.subscribe(() => {
      store.subscribe(state => late.push(state.a))
    })

    store.setState({ a: 2 })

    // it already sees the new state via getState — delivering the in-flight write too would be a
    // spurious extra notification. Iterating the live Set would have delivered it.
    expect(late).toEqual([])
    expect(store.getState()).toEqual({ a: 2 })
  })

  it('re-entrant writes leave every listener holding the final state', () => {
    const store = createStore<{ a: number }>({ a: 1 })
    const seen: number[] = []
    let reentered = false
    store.subscribe(state => {
      if (!reentered && state.a === 2) {
        reentered = true
        store.setState({ a: 3 })
      }
    })
    store.subscribe(state => seen.push(state.a))

    store.setState({ a: 2 })

    // the nested cascade runs to completion inside the outer one, then the outer one resumes and
    // re-reads the current state. So the second listener is told 3 twice and never sees 2 — which is
    // the invariant that matters: the last value a listener receives always equals getState().
    // Snapshotting the state per cascade instead would deliver 3 and then 2, ending on a stale value.
    expect(seen).toEqual([3, 3])
    expect(store.getState()).toEqual({ a: 3 })
  })
})

describe('watchStore', () => {
  it('fires only when the selected value changes, not on every write', () => {
    const store = createStore({ a: 1, b: 1 })
    const seen: Array<[number, number | undefined]> = []
    watchStore(
      store,
      state => state.a,
      (value, previous) => seen.push([value, previous])
    )

    store.setState({ a: 1, b: 2 }) // b changed, a did not
    store.setState({ a: 2, b: 2 })

    expect(seen).toEqual([[2, 1]])
  })

  it('compares tuple selectors element-wise', () => {
    const store = createStore({ a: 1, b: 1 })
    let calls = 0
    watchStore(
      store,
      state => [state.a, state.b],
      () => {
        calls++
      }
    )

    // a fresh array every time, so identity comparison alone would fire on both writes
    store.setState({ a: 1, b: 1 })
    expect(calls).toBe(0)

    store.setState({ a: 1, b: 2 })
    expect(calls).toBe(1)
  })

  it('calls back immediately with no previous value when asked', () => {
    const store = createStore({ a: 7 })
    const seen: Array<[number, number | undefined]> = []

    watchStore(
      store,
      state => state.a,
      (value, previous) => seen.push([value, previous]),
      { immediate: true }
    )

    expect(seen).toEqual([[7, undefined]])
  })

  it('honours a custom equals', () => {
    const store = createStore({ a: 1 })
    let calls = 0
    watchStore(
      store,
      state => state.a,
      () => {
        calls++
      },
      { equals: (x, y) => Math.abs(x - y) < 10 }
    )

    store.setState({ a: 5 }) // within tolerance — not a change
    expect(calls).toBe(0)

    store.setState({ a: 50 })
    expect(calls).toBe(1)
  })

  it('the returned teardown stops the watch', () => {
    const store = createStore({ a: 1 })
    let calls = 0
    const unwatch = watchStore(
      store,
      state => state.a,
      () => {
        calls++
      }
    )

    store.setState({ a: 2 })
    unwatch()
    store.setState({ a: 3 })

    expect(calls).toBe(1)
  })

  it('tracks the previous value across skipped writes', () => {
    const store = createStore({ a: 1, b: 0 })
    const seen: Array<[number, number | undefined]> = []
    watchStore(
      store,
      state => state.a,
      (value, previous) => seen.push([value, previous])
    )

    store.setState({ a: 1, b: 1 }) // skipped
    store.setState({ a: 2, b: 1 })
    store.setState({ a: 2, b: 2 }) // skipped
    store.setState({ a: 3, b: 2 })

    expect(seen).toEqual([
      [2, 1],
      [3, 2]
    ])
  })
})
