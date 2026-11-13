import type { Artifact } from '@oidcraft/adapter'
import type { ResolvedConfig } from '../config'

/** Everything issued from the authorization this artifact descends from; one without a family takes its whole grant (FR-T3). */
export const revokeFamily = async (config: ResolvedConfig, artifact: Artifact) => {
  if (artifact.familyId) await config.adapter.artifacts.revokeByFamilyId(artifact.familyId)
  else if (artifact.grantId) await config.adapter.artifacts.revokeByGrantId(artifact.grantId)
}
