import type { EpochMillis, Session } from '@oidcraft/adapter'
import { constantTimeEquals, randomString } from '@oidcraft/core'
import { storedId } from '../artifacts'
import type { ResolvedConfig } from '../config'
import { settled } from '../hooks'
import { isSecure, issuerCookie, parseCookies, serializeCookie } from './cookies'
import { endSession } from './logout'

export const SESSION_COOKIE = 'oidcraft.sid'

export const sessionCookie = (config: Pick<ResolvedConfig, 'issuerUrl'>) => issuerCookie(config, SESSION_COOKIE)

/** FR-I10: an idle lifetime counts from the last use, a sign-in being one; a session from before it was kept counts from its sign-in. */
const idleEnded = (config: ResolvedConfig, session: Session) =>
  config.ttl.sessionIdle !== undefined && (session.lastUsedAt ?? session.authTime) + config.ttl.sessionIdle * 1000 <= Date.now()

/**
 * The session, unless it ended. A session idle past `ttl.sessionIdle` ends here, as an expired one does: quietly, so the
 * refresh tokens bound to it end too (FR-T6). With `use`, it is recorded as used, at most once a minute (FR-I10).
 */
export const findLiveSession = async (
  config: ResolvedConfig,
  id: string,
  { use = false, secret }: { use?: boolean; secret?: string } = {}
) => {
  const session = await config.adapter.sessions.find(id)
  if (!session) return undefined
  // NFR-S11: a cookie opens only the session its secret is the latest of; one from before the split hashes to the id.
  if (secret !== undefined && !(await constantTimeEquals(await storedId(secret), session.secretHash ?? session.id))) return undefined
  if (idleEnded(config, session)) {
    await config.adapter.sessions.destroy(id)
    return undefined
  }
  const idle = config.ttl.sessionIdle
  const lastUsedAt = session.lastUsedAt ?? session.authTime
  if (use && idle !== undefined && Date.now() - lastUsedAt >= Math.min(60, idle / 10) * 1000) {
    const now = Date.now()
    await config.adapter.sessions.update(id, { lastUsedAt: now })
    return { ...session, lastUsedAt: now }
  }
  return session
}

/** NFR-S11: the cookie is `<id>.<secret>`, the id being the `sid` clients are told; one from before is the secret alone, its hash the id. */
const heldIn = async (config: ResolvedConfig, cookie: string | null) => {
  const value = parseCookies(cookie).get(sessionCookie(config))
  if (!value) return undefined
  const dot = value.indexOf('.')
  return dot < 0 ? { id: await storedId(value), secret: value } : { id: value.slice(0, dot), secret: value.slice(dot + 1) }
}

const sessionIn = async (config: ResolvedConfig, cookie: string | null, options: { use?: boolean } = {}) => {
  const held = await heldIn(config, cookie)
  return held ? findLiveSession(config, held.id, { ...options, secret: held.secret }) : undefined
}

export const readSession = (config: ResolvedConfig, request: Request, options?: { use?: boolean }) =>
  sessionIn(config, request.headers.get('cookie'), options)

export type LoginInput = {
  accountId: string
  acr?: string | undefined
  amr?: string[] | undefined
  idp?: string | undefined
  upstreamSessionId?: string | undefined
  authTime?: EpochMillis | undefined
}

/** What a sign-in sets, on a new session or on the browser's own one for the same account (FR-I10). */
const signedIn = (config: ResolvedConfig, login: LoginInput) => {
  const now = Date.now()
  return {
    // Never in the future: an upstream's clock, or a host's mistake, must not make a session fresher than now.
    authTime: Math.min(login.authTime ?? now, now),
    acr: login.acr,
    amr: login.amr,
    idp: login.idp,
    upstreamSessionId: login.upstreamSessionId,
    lastUsedAt: now,
    expiresAt: now + config.ttl.session * 1000
  }
}

const cookieFor = (config: ResolvedConfig, id: string, secret: string) =>
  serializeCookie(sessionCookie(config), `${id}.${secret}`, { maxAge: config.ttl.session, secure: isSecure(config) })

export const startSession = async (config: ResolvedConfig, login: LoginInput) => {
  const secret = randomString()
  const { acr, amr, idp, upstreamSessionId, ...times } = signedIn(config, login)
  const session: Session = {
    id: randomString(),
    secretHash: await storedId(secret),
    accountId: login.accountId,
    ...times,
    ...(acr && { acr }),
    ...(amr && { amr }),
    ...(idp && { idp }),
    ...(upstreamSessionId && { upstreamSessionId }),
    // FR-C11: a client joins when it is issued tokens, so one the person refused is never told who they were.
    clients: []
  }
  await config.adapter.sessions.upsert(session)
  return { session, cookie: cookieFor(config, session.id, secret) }
}

/**
 * FR-I10: a browser holds one session per issuer, and a sign-in never leaves the one it had where no logout reaches it.
 * The same account's is updated in place, its id and `sid` kept so the person's other applications stay signed in, under a
 * new secret, so a copy of the old cookie gains nothing this sign-in proved (NFR-S11). Another account's is ended first, as
 * a logout ends it.
 */
export const establishSession = async (config: ResolvedConfig, login: LoginInput, cookie: string | null) => {
  const current = await sessionIn(config, cookie)
  if (current?.accountId === login.accountId) {
    const secret = randomString()
    const fields = { ...signedIn(config, login), secretHash: await storedId(secret) }
    if (await config.adapter.sessions.update(current.id, fields)) {
      const { acr, amr, idp, upstreamSessionId, ...rest } = { ...current, ...fields }
      const session: Session = {
        ...rest,
        ...(acr && { acr }),
        ...(amr && { amr }),
        ...(idp && { idp }),
        ...(upstreamSessionId && { upstreamSessionId })
      }
      return { session, cookie: cookieFor(config, current.id, secret) }
    }
  } else if (current) {
    const { notifications, frontChannel } = await endSession(config, current)
    await settled([
      () => notifications.length && config.onLogout?.(notifications),
      () => frontChannel.length && config.onFrontChannelLogout?.(frontChannel),
      () => config.onSessionEnd?.(current, 'logout')
    ])
  }
  return startSession(config, login)
}

/** What `max_age` and `prompt=login` are measured against (FR-C16, FR-F9); `max_age=0` is `prompt=login` (OIDC Core §3.1.2.1). */
export const isFresh = (session: Session, maxAge: number | undefined) =>
  maxAge === undefined || (maxAge > 0 && Date.now() - session.authTime <= maxAge * 1000)
