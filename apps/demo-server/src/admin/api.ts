/// <reference types="bun" />
import type { Provider, Realms } from 'oidcraft'
import { ADMIN_CLIENT_ID, administrators, callerOf, FIRST_PARTY, json } from '../op/first-party'

const realmsApi = async (realms: Realms | undefined, request: Request, id: string | undefined, action: string | undefined) => {
  // The admin hides the panel on this answer, so a deployment without realms never shows one (FR-M4).
  if (!realms) return json({ enabled: false, realms: [] })
  const { management } = realms
  if (request.method === 'GET' && !id) return json({ enabled: true, realms: await management.list() })
  if (request.method === 'POST' && !id) {
    const { id: realmId, displayName } = (await request.json()) as { id: string; displayName?: string }
    return json(await management.create({ id: realmId, ...(displayName && { displayName }) }), 201)
  }
  if (!id) return undefined
  if (request.method === 'POST' && action === 'enable') return json(await management.enable(id))
  if (request.method === 'POST' && action === 'disable') return json(await management.disable(id))
  if (request.method === 'PATCH') return json(await management.update(id, (await request.json()) as { displayName?: string }))
  if (request.method === 'DELETE') {
    await management.remove(id)
    return json({ ok: true })
  }
  return undefined
}

/**
 * `?realm=acme` points every other endpoint at that realm's management: the admin of one realm is
 * the same admin, aimed elsewhere. Without it, the control plane's own.
 */
export const adminApi = async (
  provider: Provider,
  realms: Realms | undefined,
  request: Request,
  url: URL
): Promise<Response | undefined> => {
  const path = url.pathname.replace(/^\/admin\/api/, '')
  if (!path) return undefined

  const caller = await callerOf(provider, request, ADMIN_CLIENT_ID)
  if (!caller) return json({ error: 'invalid_token', error_description: 'Your sign-in has ended. Sign in again.' }, 401)
  // The decision FR-M1 leaves to the host, made here: an allowlist of account ids.
  if (!administrators().has(caller)) {
    return json({ error: 'forbidden', error_description: `${caller} is not an administrator here. Add it to OIDCRAFT_ADMINS.` }, 403)
  }

  const segments = path.split('/').filter(Boolean)
  const [resource, id, action] = segments

  try {
    if (resource === 'realms') return (await realmsApi(realms, request, id, action)) ?? json({ error: 'not_found' }, 404)

    const realm = url.searchParams.get('realm')
    const target = realm ? await realms?.get(realm) : provider
    if (!target) return json({ error: 'not_found', error_description: `there is no enabled realm ${realm}` }, 404)
    const { management } = target

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
        if (!realm && FIRST_PARTY.includes(id)) {
          return json(
            {
              error: 'conflict',
              error_description: 'the admin and account apps need this client: deleting it would lock everyone out of them'
            },
            409
          )
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
    // A refusal the operator can act on — a taken or malformed realm id — is not a server fault.
    if (resource === 'realms') return json({ error: 'invalid_request', error_description: (error as Error).message }, 400)
    console.error('[admin]', error)
    return json({ error: 'server_error', error_description: (error as Error).message }, 500)
  }
}
