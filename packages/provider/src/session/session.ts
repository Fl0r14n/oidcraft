import type { Session } from '@oidcraft/adapter'
import { randomString } from '@oidcraft/core'
import { storedId } from '../artifacts'
import type { ResolvedConfig } from '../config'
import { parseCookies, serializeCookie } from './cookies'

export const SESSION_COOKIE = 'oidcraft.sid'

/** One cookie per issuer: two issuers on one host, told apart by path, would otherwise overwrite each other's. */
export const perIssuer = (config: Pick<ResolvedConfig, 'issuerUrl'>, name: string) => {
  const path = config.issuerUrl.pathname.replace(/^\/+|\/+$/g, '')
  return path ? `${name}.${path.replace(/[^A-Za-z0-9]/g, '_')}` : name
}

export const sessionCookie = (config: Pick<ResolvedConfig, 'issuerUrl'>) => perIssuer(config, SESSION_COOKIE)

// NFR-S11: the cookie carries a secret and the session is stored under its hash, which is the `sid` clients are told.
export const readSession = async (config: ResolvedConfig, request: Request) => {
  const secret = parseCookies(request.headers.get('cookie')).get(sessionCookie(config))
  return secret ? config.adapter.sessions.find(await storedId(secret)) : undefined
}

export type LoginInput = {
  accountId: string
  acr?: string | undefined
  amr?: string[] | undefined
  idp?: string | undefined
  upstreamSessionId?: string | undefined
  authTime?: Date | undefined
}

export const startSession = async (config: ResolvedConfig, login: LoginInput, clientId: string) => {
  const secret = randomString()
  const session: Session = {
    id: await storedId(secret),
    accountId: login.accountId,
    // Never in the future: an upstream's clock, or a host's mistake, must not make a session fresher than now.
    authTime: new Date(Math.min(login.authTime?.getTime() ?? Date.now(), Date.now())),
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
    cookie: serializeCookie(sessionCookie(config), secret, {
      maxAge: config.ttl.session,
      secure: config.issuerUrl.protocol === 'https:'
    })
  }
}

/** What `max_age` and `prompt=login` are measured against (FR-C16, FR-F9); `max_age=0` is `prompt=login` (OIDC Core §3.1.2.1). */
export const isFresh = (session: Session, maxAge: number | undefined) =>
  maxAge === undefined || (maxAge > 0 && Date.now() - session.authTime.getTime() <= maxAge * 1000)
