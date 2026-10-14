/// <reference types="bun" />
import type { Adapter } from 'oidcraft'
import { optional } from './env'

export const ADMIN_CLIENT_ID = 'oidcraft-admin'
export const ADMIN_API_CLIENT_ID = 'oidcraft-admin-api'

/** Only this process introspects with it, so it is minted per boot and never written down. */
export const adminApiSecret = crypto.randomUUID()

/**
 * Who may administer this deployment: account ids from OIDCRAFT_ADMINS. The library never decides
 * this (FR-M1). Empty means nobody, never everybody.
 */
export const administrators = () =>
  new Set(
    (optional('OIDCRAFT_ADMINS') ?? '')
      .split(',')
      .map(id => id.trim())
      .filter(Boolean)
  )

/**
 * The admin app is an ordinary public client of this OP, and its API an ordinary resource server
 * that introspects what the app sends. Both are re-registered at boot so the secret is current.
 */
export const seedAdminClients = async (adapter: Adapter, issuer: string) => {
  const now = new Date()
  await adapter.clients.upsert?.({
    clientId: ADMIN_CLIENT_ID,
    clientName: 'oidcraft admin',
    redirectUris: [`${issuer}/admin/callback`],
    postLogoutRedirectUris: [`${issuer}/admin`],
    grantTypes: ['authorization_code', 'refresh_token'],
    responseTypes: ['code'],
    scopes: ['openid', 'profile'],
    tokenEndpointAuthMethod: 'none',
    requirePkce: true,
    // The allowlist names account ids, so the subject must be one rather than a pairwise alias.
    subjectType: 'public',
    createdAt: now,
    updatedAt: now
  })
  await adapter.clients.upsert?.({
    clientId: ADMIN_API_CLIENT_ID,
    clientSecret: adminApiSecret,
    clientName: 'oidcraft admin API',
    redirectUris: [],
    grantTypes: [],
    responseTypes: [],
    scopes: [],
    tokenEndpointAuthMethod: 'client_secret_basic',
    resourceServer: true,
    createdAt: now,
    updatedAt: now
  })
}
