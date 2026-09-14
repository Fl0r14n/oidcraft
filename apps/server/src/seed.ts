/// <reference types="bun" />
import type { AccountStore, Adapter } from 'oidcraft'
import { withDefault } from './env'

/** Demo only: any account name works and the claims are synthetic (`G-2` — the host owns the directory). */
export const demoAccounts: AccountStore = {
  async find(accountId) {
    return { accountId, claims: {} }
  },
  async claims(accountId, scopes) {
    return {
      ...(scopes.includes('profile') && { name: accountId, preferred_username: accountId, updated_at: Math.floor(Date.now() / 1000) }),
      ...(scopes.includes('email') && { email: `${accountId}@example.invalid`, email_verified: false })
    }
  }
}

/** The demo relying party in apps/client. A real deployment registers clients through the admin API. */
export const seedDemoClient = async (adapter: Adapter) => {
  const clientId = withDefault('OIDCRAFT_PUBLIC_CLIENT_ID', 'demo-client')
  const origin = withDefault('OIDCRAFT_PUBLIC_ORIGIN', 'http://localhost:3000')
  if (await adapter.clients.find(clientId)) return

  await adapter.clients.create?.({
    clientId,
    clientName: 'oidcraft demo client',
    redirectUris: [`${origin}/oauth_callback`],
    postLogoutRedirectUris: [`${origin}/`],
    grantTypes: ['authorization_code', 'refresh_token', 'urn:ietf:params:oauth:grant-type:device_code'],
    responseTypes: ['code'],
    scopes: ['openid', 'profile', 'email', 'offline_access'],
    // Public: a browser app cannot keep a secret, so PKCE is what protects the code (FR-C3).
    tokenEndpointAuthMethod: 'none',
    requirePkce: true,
    createdAt: new Date(),
    updatedAt: new Date()
  })
  console.log(`[oidcraft] registered demo client ${clientId} -> ${origin}/oauth_callback`)
}
