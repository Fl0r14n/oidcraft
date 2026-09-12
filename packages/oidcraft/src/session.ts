import type { ResolvedConfig } from './config'
import { parseCookies, serializeCookie } from './cookies'
import { token } from './random'
import type { Session } from './types'

export const SESSION_COOKIE = 'oidcraft.sid'

export const readSession = async (config: ResolvedConfig, request: Request) => {
  const id = parseCookies(request.headers.get('cookie')).get(SESSION_COOKIE)
  return id ? config.adapter.sessions.find(id) : undefined
}

export type LoginInput = {
  accountId: string
  acr?: string | undefined
  amr?: string[] | undefined
  idp?: string | undefined
  upstreamSessionId?: string | undefined
}

export const startSession = async (config: ResolvedConfig, login: LoginInput, clientId: string) => {
  const session: Session = {
    id: token(),
    accountId: login.accountId,
    authTime: new Date(),
    ...(login.acr && { acr: login.acr }),
    ...(login.amr && { amr: login.amr }),
    ...(login.idp && { idp: login.idp }),
    ...(login.upstreamSessionId && { upstreamSessionId: login.upstreamSessionId }),
    clients: [clientId],
    expiresAt: new Date(Date.now() + config.ttl.session * 1000)
  }
  await config.adapter.sessions.upsert(session)
  return {
    session,
    cookie: serializeCookie(SESSION_COOKIE, session.id, {
      maxAge: config.ttl.session,
      secure: config.issuerUrl.protocol === 'https:'
    })
  }
}

/** A session's age is what `max_age` and `prompt=login` are measured against (FR-C16, FR-F9). */
export const isFresh = (session: Session, maxAge: number | undefined) =>
  maxAge === undefined || Date.now() - session.authTime.getTime() <= maxAge * 1000
