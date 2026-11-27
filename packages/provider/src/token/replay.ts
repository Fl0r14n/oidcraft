import { storedId } from '../artifacts'
import type { ResolvedConfig } from '../config'
import { OAuthError } from '../errors'
import type { Stored } from '../payloads'
import { revokeFamily } from './family'

type SingleUse = Stored<'authorization_code' | 'refresh_token'>

// A replay means it leaked: revoke its family, not the grant's others (FR-T3, FR-T4, NFR-S4, RFC 9700 §4.14.2).
// FR-M3: reported by the side that presented the replay; the redemption it raced loses its tokens without a second report.
export const revokeOnReplay = async (config: ResolvedConfig, artifact: SingleUse, what: string, presentedBy: string | undefined) => {
  await replayed(config, artifact)
  await revokeFamily(config, artifact)
  throw new OAuthError('invalid_grant', {
    description: `this ${what} was already used; every token issued from it has been revoked`,
    spec: 'RFC 9700 §4.14.2',
    ...(presentedBy !== undefined && {
      event: {
        action: 'token.replay',
        clientId: artifact.clientId,
        ...(artifact.accountId && { accountId: artifact.accountId }),
        ...(artifact.grantId && { grantId: artifact.grantId }),
        detail: { kind: artifact.kind, presentedBy, ...(artifact.familyId && { familyId: artifact.familyId }) }
      }
    })
  })
}

/** How long a replay is remembered: longer than any redemption takes to write its tokens. */
const REPLAY_WINDOW = 60

// A replay claims this before revoking, the winner after writing; `false` for the winner means the revocation missed its tokens.
const replayed = async (config: ResolvedConfig, artifact: SingleUse) =>
  !(await config.adapter.replay.claim('redeemed', await storedId(`${artifact.kind}:${artifact.id}`), REPLAY_WINDOW))

/** NFR-S4: tokens written after a concurrent replay revoked the family must not outlive it. */
export const unlessReplayed = async <T>(config: ResolvedConfig, artifact: SingleUse, what: string, tokens: T) => {
  if (await replayed(config, artifact)) await revokeOnReplay(config, artifact, what, undefined)
  return tokens
}
