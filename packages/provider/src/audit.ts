import type { AuditEvent, ResolvedConfig } from './config'

/** Every write through registration or management, and every attack detected, is reported to the host (FR-M3). */
export const audit = async (config: ResolvedConfig, action: string, detail: Omit<AuditEvent, 'action' | 'at'>) =>
  config.onAudit?.({ action, at: new Date(), ...detail })
