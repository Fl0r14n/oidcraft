import type { Artifact } from '@oidcraft/adapter'
import type { ResolvedConfig } from '../config'
import { OAuthError } from '../errors'
import { readArtifact, writeArtifact } from '../payloads'

/** Everything issued from the authorization this artifact descends from; one without a family takes its whole grant (FR-T3). */
export const revokeFamily = async (config: ResolvedConfig, artifact: Pick<Artifact, 'familyId' | 'grantId'>) => {
  if (artifact.familyId) {
    // Marked before the sweep: a write the sweep misses finds the mark instead (see `assertFamilyLive`).
    await writeArtifact(config.adapter.artifacts, {
      id: artifact.familyId,
      kind: 'revoked_family',
      clientId: '',
      payload: {},
      expiresAt: new Date(Date.now() + config.ttl.refreshTokenFamily * 1000)
    })
    await config.adapter.artifacts.revokeByFamilyId(artifact.familyId)
  } else if (artifact.grantId) await config.adapter.artifacts.revokeByGrantId(artifact.grantId)
}

/**
 * After writing into a family: a revocation that ran meanwhile, of the family or of its grant, takes
 * what was just written too. Either this sees its mark, or its sweep, which follows the mark, saw the write.
 */
export const assertFamilyLive = async (config: ResolvedConfig, familyId: string, grantId: string) => {
  const revoked = await readArtifact(config.adapter.artifacts, 'revoked_family', familyId)
  if (!revoked && (await config.adapter.grants.find(grantId))) return
  await config.adapter.artifacts.revokeByFamilyId(familyId)
  throw new OAuthError('invalid_grant', { description: 'this authorization was revoked while it was being used', spec: 'RFC 9700 §4.14.2' })
}
