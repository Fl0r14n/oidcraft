export type MemoryAdapterOptions = {
  /** Sweep interval for expired artifacts. Zero disables it; nothing else prunes (NFR-P3). */
  pruneIntervalMs?: number
}
