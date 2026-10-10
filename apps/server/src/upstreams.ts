/// <reference types="bun" />
import { pickClaims, type UpstreamProvider } from 'oidcraft/federation'
import { issuer, optional } from './env'

/** Where every upstream sends the browser back; the handoff's state says which one it was. */
export const callbackUri = () => `${issuer()}/federation/callback`

const google = (): UpstreamProvider | undefined => {
  const clientId = optional('UPSTREAM_GOOGLE_CLIENT_ID')
  const clientSecret = optional('UPSTREAM_GOOGLE_CLIENT_SECRET')
  if (!clientId || !clientSecret) return undefined
  return {
    id: 'google',
    label: 'Google',
    issuer: 'https://accounts.google.com',
    clientId,
    clientSecret,
    scopes: ['openid', 'email', 'profile'],
    domains: ['gmail.com'],
    claimMapper: pickClaims()
  }
}

/** Each upstream is on only when its credentials are set, so a bare checkout has local accounts only. */
export const upstreams = [google()].filter((upstream): upstream is UpstreamProvider => upstream !== undefined)
