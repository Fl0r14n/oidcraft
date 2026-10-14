/// <reference types="bun" />
import type { Provider } from 'oidcraft'
import { ADMIN_API_CLIENT_ID, ADMIN_CLIENT_ID, adminApiSecret, administrators } from '../op/admin'

const json = (body: unknown, status = 200) => Response.json(body, { status, headers: { 'cache-control': 'no-store' } })

/**
 * Who is calling, by introspecting their bearer token in this process (RFC 7662). Only a live token
 * issued to the admin app counts: one the same person holds for another client does not.
 */
const callerOf = async (provider: Provider, request: Request) => {
  const header = request.headers.get('authorization')
  if (!header?.toLowerCase().startsWith('bearer ')) return undefined
  const credentials = btoa(`${encodeURIComponent(ADMIN_API_CLIENT_ID)}:${encodeURIComponent(adminApiSecret)}`)
  const response = await provider.handle(
    new Request(`${provider.config.issuer}${provider.config.routes.introspection}`, {
      method: 'POST',
      headers: { authorization: `Basic ${credentials}`, 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ token: header.slice(7).trim() })
    })
  )
  const body = (await response.json()) as { active?: boolean; client_id?: string; sub?: string }
  return body.active && body.client_id === ADMIN_CLIENT_ID ? body.sub : undefined
}

export const adminApi = async (provider: Provider, request: Request, url: URL): Promise<Response | undefined> => {
  const path = url.pathname.replace(/^\/admin\/api/, '')
  if (!path) return undefined

  const caller = await callerOf(provider, request)
  if (!caller) return json({ error: 'invalid_token', error_description: 'Your sign-in has ended. Sign in again.' }, 401)
  // The decision FR-M1 leaves to the host, made here: an allowlist of account ids.
  if (!administrators().has(caller)) {
    return json({ error: 'forbidden', error_description: `${caller} is not an administrator here. Add it to OIDCRAFT_ADMINS.` }, 403)
  }

  const { management } = provider
  const segments = path.split('/').filter(Boolean)
  const [resource, id, action] = segments

  try {
    if (resource === 'clients') {
      if (request.method === 'GET' && !id) return json(await management.clients.list())
      if (request.method === 'GET' && id) {
        const client = await management.clients.get(id)
        return client ? json(management.clients.describe(client)) : json({ error: 'not_found' }, 404)
      }
      if (request.method === 'POST') return json(await management.clients.create(await request.json()), 201)
      if (request.method === 'PATCH' && id) {
        await management.clients.update(id, await request.json())
        return json({ ok: true })
      }
      if (request.method === 'DELETE' && id) {
        if (id === ADMIN_CLIENT_ID || id === ADMIN_API_CLIENT_ID) {
          return json({ error: 'conflict', error_description: 'deleting the admin app’s own client would lock every operator out' }, 409)
        }
        await management.clients.destroy(id)
        return json({ ok: true })
      }
    }

    if (resource === 'accounts' && id) {
      if (action === 'grants' && request.method === 'GET') return json(await management.grants.listForAccount(id))
      if (action === 'sessions' && request.method === 'GET') return json(await management.sessions.listForAccount(id))
      if (action === 'identities' && request.method === 'GET') return json(await management.identities.listForAccount(id))
    }

    if (resource === 'grants' && id && request.method === 'DELETE') {
      await management.grants.revoke(id)
      return json({ ok: true })
    }

    if (resource === 'sessions' && id && request.method === 'DELETE') {
      const notifications = await management.sessions.destroy(id)
      return json({ ok: true, notified: notifications.map(notification => notification.clientId) })
    }

    if (resource === 'keys' && request.method === 'GET') return json({ keys: await management.keys.list() })

    if (resource === 'upstreams' && request.method === 'GET') return json({ upstreams: management.upstreams.list() })

    return json({ error: 'not_found' }, 404)
  } catch (error) {
    console.error('[admin]', error)
    return json({ error: 'server_error', error_description: (error as Error).message }, 500)
  }
}
