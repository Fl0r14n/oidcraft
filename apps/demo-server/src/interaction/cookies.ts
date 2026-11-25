/// <reference types="bun" />
import { base64url } from 'jose'
import { issuer } from '../op/env'

/** Per process: a restart only loses half-finished sign-ins and the account list, both cheap to redo. */
const key = await crypto.subtle.importKey('raw', crypto.getRandomValues(new Uint8Array(32)), { name: 'HMAC', hash: 'SHA-256' }, false, [
  'sign',
  'verify'
])
const secure = new URL(issuer()).protocol === 'https:'

const read = (request: Request, name: string) =>
  request.headers
    .get('cookie')
    ?.split(';')
    .map(pair => pair.trim().split('='))
    .find(([cookieName]) => cookieName === name)?.[1]

const serialize = (name: string, value: string, maxAge: number, path: string) =>
  `${name}=${value}; Path=${path}; Max-Age=${maxAge}; HttpOnly; SameSite=Lax${secure ? '; Secure' : ''}`

const sign = async (payload: unknown) => {
  const body = base64url.encode(JSON.stringify(payload))
  const mac = base64url.encode(new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(body))))
  return `${body}.${mac}`
}

const verified = async <T>(value: string | undefined): Promise<T | undefined> => {
  const [body, mac] = value?.split('.') ?? []
  if (!body || !mac) return undefined
  try {
    const valid = await crypto.subtle.verify('HMAC', key, base64url.decode(mac) as BufferSource, new TextEncoder().encode(body))
    return valid ? (JSON.parse(new TextDecoder().decode(base64url.decode(body))) as T) : undefined
  } catch {
    return undefined
  }
}

const PENDING = 'oidcraft.demo.pending'
const KNOWN = 'oidcraft.demo.known'

const pendingOf = async (request: Request, interactionId: string) => {
  const pending = await verified<Pending>(read(request, PENDING))
  return pending && pending.interactionId === interactionId && pending.until > Date.now() ? pending : undefined
}

type Pending = { interactionId: string; accountId: string; until: number; byEmail?: true }

/** A right first factor awaiting its second, bound to the interaction; `byEmail` may finish in another browser (FR-I9). */
export const pendingSecondFactor = {
  set: async (interactionId: string, accountId: string, byEmail = false) =>
    serialize(
      PENDING,
      await sign({ interactionId, accountId, until: Date.now() + 600_000, ...(byEmail && { byEmail }) } satisfies Pending),
      600,
      '/interaction'
    ),
  get: async (request: Request, interactionId: string) => (await pendingOf(request, interactionId))?.accountId,
  byEmail: async (request: Request, interactionId: string) => Boolean((await pendingOf(request, interactionId))?.byEmail),
  clear: () => serialize(PENDING, '', 0, '/interaction')
}

/** The usernames this browser has signed in with, for `prompt=select_account`. Signed so the list cannot be planted. */
export const knownAccounts = {
  get: async (request: Request) => (await verified<string[]>(read(request, KNOWN))) ?? [],
  add: async (request: Request, username: string) => {
    const known = [username, ...(await knownAccounts.get(request)).filter(name => name !== username)].slice(0, 5)
    return serialize(KNOWN, await sign(known), 30 * 24 * 3600, '/interaction')
  }
}

const RESUME = 'oidcraft.demo.resume'

/** The sign-in a reset was asked from, so finishing it leads back there; a cookie, so a link opened elsewhere resumes nothing. */
export const resumeAfterReset = {
  set: async (interactionId: string) => serialize(RESUME, await sign({ interactionId, until: Date.now() + 1_800_000 }), 1800, '/reset'),
  get: async (request: Request) => {
    const resume = await verified<{ interactionId: string; until: number }>(read(request, RESUME))
    return resume && resume.until > Date.now() ? resume.interactionId : undefined
  },
  clear: () => serialize(RESUME, '', 0, '/reset')
}
