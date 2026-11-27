/// <reference types="bun" />
import type { Adapter, CredentialsAdapter, Provider } from '@oidcraft/provider'
import { optional } from './env'

export const ADMIN_CLIENT_ID = 'oidcraft-admin'
export const ACCOUNT_CLIENT_ID = 'oidcraft-account'
export const FIRST_PARTY = [ADMIN_CLIENT_ID, ACCOUNT_CLIENT_ID]

/** The library never decides who administers (FR-M1): OIDCRAFT_ADMINS names usernames, and empty means nobody, never everybody. */
const administrators = () =>
  new Set(
    (optional('OIDCRAFT_ADMINS') ?? '')
      .split(',')
      .map(id => id.trim())
      .filter(Boolean)
  )

const publicClient = (clientId: string, clientName: string, issuer: string, path: string) => {
  const now = new Date()
  return {
    clientId,
    clientName,
    redirectUris: [`${issuer}${path}/callback`],
    postLogoutRedirectUris: [`${issuer}${path}`],
    grantTypes: ['authorization_code', 'refresh_token'],
    responseTypes: ['code'],
    scopes: ['openid', 'profile'],
    tokenEndpointAuthMethod: 'none' as const,
    requirePkce: true,
    subjectType: 'public' as const,
    createdAt: now,
    updatedAt: now
  }
}

/** Re-registered at boot, so a changed issuer reaches their redirect URIs. */
export const seedFirstPartyClients = async (adapter: Adapter, issuer: string) => {
  await adapter.clients.upsert?.(publicClient(ADMIN_CLIENT_ID, 'oidcraft admin', issuer, '/admin'))
  await adapter.clients.upsert?.(publicClient(ACCOUNT_CLIENT_ID, 'oidcraft account', issuer, '/account'))
}

/** By username, so OIDCRAFT_ADMINS names people; an account with no local credential, a brokered one, administers nothing. */
export const administratorName = async (provider: Provider, accountId: string) => {
  const credential = await (provider.config.adapter as Partial<CredentialsAdapter>).credentials?.find(accountId)
  return credential && administrators().has(credential.username) ? credential.username : undefined
}

/** D-8: a live token issued to `clientId` for no resource, a DPoP-bound one only with its proof; its account, or nothing. */
export const callerOf = async (provider: Provider, request: Request, clientId: string) => {
  const verified = await provider.verifyAccessToken(request)
  return verified.ok && verified.token.clientId === clientId ? verified.token.accountId : undefined
}

export const json = (body: unknown, status = 200) => Response.json(body, { status, headers: { 'cache-control': 'no-store' } })
