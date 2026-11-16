import type { ResolvedConfig } from './config'

/** NFR-D5: a host hook failing is reported, and never changes the answer to what already happened. */
export const reportError = (config: ResolvedConfig, request: Request, error: unknown) =>
  Promise.resolve()
    .then(() => config.onError?.(error, { request }))
    .catch(() => undefined)

export const guarded = async (config: ResolvedConfig, request: Request, hook: () => unknown) => {
  try {
    await hook()
  } catch (error) {
    await reportError(config, request, error)
  }
}

/** FR-M3: with no request to report against, every event still runs, and the first failure reaches the caller. */
export const settled = async (events: (() => unknown)[]) => {
  const failures: unknown[] = []
  for (const event of events) {
    try {
      await event()
    } catch (error) {
      failures.push(error)
    }
  }
  if (failures.length) throw failures[0]
}
