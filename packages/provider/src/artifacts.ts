import type { Adapter, ArtifactKind, ArtifactStore } from '@oidcraft/adapter'
import { sha256 } from '@oidcraft/core'
import { base64url } from 'jose'

/**
 * The kinds whose id is the credential. Left out: `user_code`, typed by a person and too short for
 * a hash to hide; `password_reset` and `broker_handoff`, which `./accounts` and `./broker` write
 * through the host's own adapter; and ids that are not secrets at all (NFR-S11).
 */
const BEARER: ReadonlySet<ArtifactKind> = new Set<ArtifactKind>([
  'authorization_code',
  'access_token',
  'refresh_token',
  'device_code',
  'pushed_authorization_request',
  'backchannel_authentication_request',
  'interaction',
  'authorization_response'
])

/** Unsalted on purpose: every value hashed here is 288 random bits, so there is nothing to precompute (NFR-S11). */
export const storedId = async (value: string) => base64url.encode(await sha256(value))

const idFor = (kind: ArtifactKind, id: string) => (BEARER.has(kind) ? storedId(id) : id)

/**
 * NFR-S11: a bearer artifact is stored under a hash of its value. A record found by its value comes
 * back carrying that value as its id, so it can be written again; one found any other way —
 * `findByUserCode` — carries the stored id and must not be written back.
 */
const hashedArtifacts = (store: ArtifactStore): ArtifactStore => ({
  ...store,
  async find(kind, id) {
    const artifact = await store.find(kind, await idFor(kind, id))
    return artifact && { ...artifact, id }
  },
  async upsert(artifact) {
    await store.upsert({ ...artifact, id: await idFor(artifact.kind, artifact.id) })
  },
  async consume(kind, id) {
    return store.consume(kind, await idFor(kind, id))
  },
  async destroy(kind, id) {
    await store.destroy(kind, await idFor(kind, id))
  }
})

export const withHashedArtifacts = (adapter: Adapter): Adapter => ({ ...adapter, artifacts: hashedArtifacts(adapter.artifacts) })
