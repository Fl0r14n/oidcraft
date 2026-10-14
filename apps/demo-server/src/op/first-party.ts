/// <reference types="bun" />
import type { Adapter, Provider } from 'oidcraft'
import { optional } from './env'

export const ADMIN_CLIENT_ID = 'oidcraft-admin'
export const ACCOUNT_CLIENT_ID = 'oidcraft-account'
/** The resource server both apps' APIs introspect as. Not a client anyone signs in to. */
export const API_CLIENT_ID = 'oidcraft-api'
export const FIRST_PARTY = [ADMIN_CLIENT_ID, ACCOUNT_CLIENT_ID, API_CLIENT_ID]

/** Only this process introspects with it, so it is minted per boot and never written down. */
const apiSecret = crypto.randomUUID()

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
    // Both APIs act on account ids, so the subject must be one rather than a pairwise alias.
    subjectType: 'public' as const,
    createdAt: now,
    updatedAt: now
  }
}

/**
 * The admin and account apps are ordinary public clients of this OP, and their APIs one resource
 * server that introspects what the apps send. Re-registered at boot so the secret is current.
 */
export const seedFirstPartyClients = async (adapter: Adapter, issuer: string) => {
  await adapter.clients.upsert?.(publicClient(ADMIN_CLIENT_ID, 'oidcraft admin', issuer, '/admin'))
  await adapter.clients.upsert?.(publicClient(ACCOUNT_CLIENT_ID, 'oidcraft account', issuer, '/account'))
  const now = new Date()
  await adapter.clients.upsert?.({
    clientId: API_CLIENT_ID,
    clientSecret: apiSecret,
    clientName: 'oidcraft first-party API',
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

/**
 * Who is calling, by introspecting their bearer token in this process (RFC 7662). Only a live token
 * issued to `clientId` counts: one the same person holds for another client does not.
 */
export const callerOf = async (provider: Provider, request: Request, clientId: string) => {
  const header = request.headers.get('authorization')
  if (!header?.toLowerCase().startsWith('bearer ')) return undefined
  const credentials = btoa(`${encodeURIComponent(API_CLIENT_ID)}:${encodeURIComponent(apiSecret)}`)
  const response = await provider.handle(
    new Request(`${provider.config.issuer}${provider.config.routes.introspection}`, {
      method: 'POST',
      headers: { authorization: `Basic ${credentials}`, 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ token: header.slice(7).trim() })
    })
  )
  const body = (await response.json()) as { active?: boolean; client_id?: string; sub?: string }
  return body.active && body.client_id === clientId ? body.sub : undefined
}

export const json = (body: unknown, status = 200) => Response.json(body, { status, headers: { 'cache-control': 'no-store' } })
