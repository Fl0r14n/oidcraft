import type { AuditEvent, ResolvedConfig } from './config'

/** Every write through registration or management is reported to the host, which decides where it goes (FR-M3). */
export const audit = async (config: ResolvedConfig, action: string, detail: Omit<AuditEvent, 'action' | 'at'>) =>
  config.onAudit?.({ action, at: new Date(), ...detail })
