/// <reference types="bun" />
import type { Provider } from 'oidcraft'
import { optional } from '../env'

/**
 * A JSON surface over `provider.management`, mounted by this app behind its own check.
 *
 * The library deliberately exposes management as functions rather than routes so the host decides
 * who is an administrator (FR-M1). This is that decision, made here — and it is a *demo* one: a
 * shared bearer token from the environment. A real deployment authenticates its operators properly.
 */
const authorized = (request: Request) => {
  const expected = optional('OIDCRAFT_ADMIN_TOKEN')
  if (!expected) return false
  const header = request.headers.get('authorization')
  return header?.toLowerCase().startsWith('bearer ') && header.slice(7).trim() === expected
}

const json = (body: unknown, status = 200) => Response.json(body, { status, headers: { 'cache-control': 'no-store' } })

export const adminApi = async (provider: Provider, request: Request, url: URL): Promise<Response | undefined> => {
  const path = url.pathname.replace(/^\/admin\/api/, '')
  if (!path) return undefined

  if (!authorized(request)) {
    return json({ error: 'unauthorized', error_description: 'set OIDCRAFT_ADMIN_TOKEN and send it as a bearer token' }, 401)
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

    return json({ error: 'not_found' }, 404)
  } catch (error) {
    console.error('[admin]', error)
    return json({ error: 'server_error', error_description: (error as Error).message }, 500)
  }
}
