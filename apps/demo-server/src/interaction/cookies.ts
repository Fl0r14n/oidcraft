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

/**
 * A password that was right, waiting for its second factor. Bound to the interaction, so it cannot
 * finish any other sign-in, and short-lived, so a walked-away screen does not stay half signed in.
 */
export const pendingSecondFactor = {
  set: async (interactionId: string, accountId: string) =>
    serialize(PENDING, await sign({ interactionId, accountId, until: Date.now() + 300_000 }), 300, '/interaction'),
  get: async (request: Request, interactionId: string) => {
    const pending = await verified<{ interactionId: string; accountId: string; until: number }>(read(request, PENDING))
    return pending && pending.interactionId === interactionId && pending.until > Date.now() ? pending.accountId : undefined
  },
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
