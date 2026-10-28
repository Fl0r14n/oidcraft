import { shallowRef } from 'vue'
import { useApi } from '../shared/api'

export type AdminClient = {
  clientId: string
  clientName?: string
  redirectUris: string[]
  grantTypes: string[]
  scopes: string[]
  tokenEndpointAuthMethod: string
  createdAt: string
}

export type AdminRealm = { id: string; displayName?: string; enabled: boolean; createdAt: string }

export { failureMessage } from '../shared/api'

/** The realm the panels manage; empty is the control plane itself. */
export const currentRealm = shallowRef('')

/** Every call but the realm list itself is aimed at the current realm. */
export const useAdminApi = () => {
  const api = useApi('/admin/api')
  return <T>(path: string, init?: RequestInit) => {
    const realm = currentRealm.value
    if (!realm || path.startsWith('/realms')) return api<T>(path, init)
    return api<T>(`${path}${path.includes('?') ? '&' : '?'}realm=${encodeURIComponent(realm)}`, init)
  }
}
