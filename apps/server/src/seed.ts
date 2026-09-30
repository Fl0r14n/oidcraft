/// <reference types="bun" />
import type { AccountStore, Adapter } from 'oidcraft'
import { optional, withDefault } from './env'

/** Demo only: any account name works and the claims are synthetic (`G-2` — the host owns the directory). */
export const demoAccounts: AccountStore = {
  async find(accountId) {
    return { accountId, claims: {} }
  },
  async claims(accountId, scopes) {
    return {
      ...(scopes.includes('profile') && {
        name: accountId,
        given_name: accountId,
        middle_name: 'Q',
        family_name: 'Demo',
        nickname: accountId,
        preferred_username: accountId,
        profile: `https://example.invalid/${accountId}`,
        picture: `https://example.invalid/${accountId}.png`,
        website: 'https://example.invalid',
        gender: 'unspecified',
        birthdate: '0000-01-01',
        zoneinfo: 'Europe/London',
        locale: 'en',
        updated_at: Math.floor(Date.now() / 1000)
      }),
      ...(scopes.includes('email') && { email: `${accountId}@example.invalid`, email_verified: false })
    }
  }
}

/** The demo relying party in apps/demo-vue. A real deployment registers clients through the admin API. */
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

type PlanClient = { client_id: string; client_secret: string }

/**
 * The OpenID Foundation suite's two static clients, only when OIDCRAFT_CONFORMANCE_SUITE names the
 * suite's base URL. Read from conformance/plan.json so the credentials exist in one place.
 */
export const seedConformanceClients = async (adapter: Adapter) => {
  const suite = optional('OIDCRAFT_CONFORMANCE_SUITE')
  if (!suite) return
  const plan = await Bun.file(new URL('../../../conformance/plan.json', import.meta.url)).json()
  const callback = `${suite.replace(/\/$/, '')}/test/a/${plan.alias}/callback`

  const clients: [PlanClient, 'client_secret_basic' | 'client_secret_post'][] = [
    [plan.client, 'client_secret_basic'],
    [plan.client2, 'client_secret_basic'],
    [plan.client_secret_post, 'client_secret_post']
  ]
  for (const [entry, method] of clients) {
    if (await adapter.clients.find(entry.client_id)) continue
    await adapter.clients.create?.({
      clientId: entry.client_id,
      clientSecret: entry.client_secret,
      clientName: `conformance suite (${entry.client_id})`,
      redirectUris: [callback],
      grantTypes: ['authorization_code', 'refresh_token'],
      responseTypes: ['code'],
      // Every scope the demo serves: which ones a module asks for is the suite's choice, not the plan's.
      scopes: ['openid', 'profile', 'email', 'offline_access'],
      tokenEndpointAuthMethod: method,
      // The suite sends a nonce but no PKCE; vouching for it is the host's call (FR-C3).
      requirePkce: false,
      createdAt: new Date(),
      updatedAt: new Date()
    })
  }
  console.log(`[oidcraft] registered the conformance suite's clients -> ${callback}`)
}
